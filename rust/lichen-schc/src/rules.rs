//! LICHEN-specific SCHC rules (RFC 8724 Section 7).
//!
//! This module defines the compression rules specific to the LICHEN protocol.
//! The core types (Mo, Cda, FieldDescriptor, Rule) are re-exported from the
//! `schc` crate at the crate root.

use lichen_core::constants::{
    RULE_GLOBAL_COAP, RULE_GLOBAL_OSCORE, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP,
    RULE_LINK_LOCAL_OSCORE, RULE_RPL_DAO, RULE_RPL_DIO, RULE_UNCOMPRESSED,
};

// Import types from the schc crate
use schc::compress::{Cda, FieldDescriptor, Mo, Rule};

// ---------------------------------------------------------------------------
// Rule Versioning (spec section 5.7)
// ---------------------------------------------------------------------------

/// Current SCHC rule set version.
///
/// Version history:
///   0 - Reserved (uncompressed fallback)
///   1 - Legacy experimental (not interoperable)
///   2 - RFC 8724 fragmentation profile
///   3 - Canonical specialized Rule 7 MQTT-SN residue
pub const RULE_SET_VERSION: u8 = 3;

/// DIO Rule Version Option type (LICHEN extension, spec section 5.7).
/// Advertised in RPL DIO messages to indicate the SCHC rule set version.
pub const SCHC_RULE_VERSION_TYPE: u8 = 0x13;

/// SCHC Rule Set Version Option for DIO messages (spec section 5.7).
///
/// This option is carried in RPL DIO messages to advertise the sender's
/// SCHC rule set version. Nodes should only join a DODAG if their rule
/// set version matches the advertised version.
///
/// Wire format:
/// ```text
/// +--------+--------+---------+
/// | Type   | Length | Version |
/// +--------+--------+---------+
///    1B       1B       1B
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchcRuleVersionOption {
    /// 8-bit unsigned rule set version (0 reserved, 1 legacy, 3 current).
    pub version: u8,
}

impl SchcRuleVersionOption {
    /// Retain a remotely advertised version for explicit compatibility checks.
    pub const fn new(version: u8) -> Self {
        Self { version }
    }

    /// Create an option for a locally implemented registry.
    pub const fn local(version: u8) -> Option<Self> {
        if version == RULE_SET_VERSION {
            Some(Self { version })
        } else {
            None
        }
    }

    /// Create an option with the current rule set version.
    pub const fn current() -> Self {
        Self {
            version: RULE_SET_VERSION,
        }
    }

    /// Serialize to wire format (Type/Length/Version).
    pub const fn to_bytes(&self) -> [u8; 3] {
        [SCHC_RULE_VERSION_TYPE, 1, self.version]
    }

    /// Parse from wire format.
    ///
    /// Returns `None` if the data is malformed (too short, wrong type, or wrong length).
    pub const fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() != 3 {
            return None;
        }
        if data[0] != SCHC_RULE_VERSION_TYPE {
            return None;
        }
        if data[1] != 1 {
            return None;
        }
        Some(Self { version: data[2] })
    }

    /// Returns true if this version matches the current rule set version.
    pub const fn is_current(&self) -> bool {
        self.version == RULE_SET_VERSION
    }
}

/// Full compressed/fragmented compatibility exists only for implemented v3.
pub const fn versions_compatible(local: u8, remote: u8) -> bool {
    local == RULE_SET_VERSION && remote == RULE_SET_VERSION
}

// ---------------------------------------------------------------------------
const LINK_LOCAL_PREFIX_TV: u128 = 0xfe80_0000_0000_0000_0000_0000_0000_0000;
const GLOBAL_PREFIX_TV: u128 = 0x0200_0000_0000_0000_0000_0000_0000_0000;

// ---------------------------------------------------------------------------
// Individual field descriptors for reuse across rules
// ---------------------------------------------------------------------------

// IPv6 base fields
const FD_IPV6_VERSION: FieldDescriptor =
    FieldDescriptor::new("IPv6.version", 4, Mo::Equal, Cda::NotSent, 6, None, None);
const FD_IPV6_TRAFFIC_CLASS: FieldDescriptor = FieldDescriptor::new(
    "IPv6.traffic_class",
    8,
    Mo::Equal,
    Cda::NotSent,
    0,
    None,
    None,
);
const FD_IPV6_FLOW_LABEL: FieldDescriptor = FieldDescriptor::new(
    "IPv6.flow_label",
    20,
    Mo::Equal,
    Cda::NotSent,
    0,
    None,
    None,
);
const FD_IPV6_PAYLOAD_LENGTH: FieldDescriptor = FieldDescriptor::new(
    "IPv6.payload_length",
    16,
    Mo::Ignore,
    Cda::Compute,
    0,
    None,
    None,
);
const FD_IPV6_HOP_LIMIT: FieldDescriptor = FieldDescriptor::new(
    "IPv6.hop_limit",
    8,
    Mo::Ignore,
    Cda::ValueSent,
    0,
    None,
    None,
);

// Link-local address fields
const FD_IPV6_SRC_LL: FieldDescriptor = FieldDescriptor::new(
    "IPv6.src",
    128,
    Mo::Msb,
    Cda::Lsb,
    LINK_LOCAL_PREFIX_TV,
    Some(64),
    None,
);
const FD_IPV6_DST_LL: FieldDescriptor = FieldDescriptor::new(
    "IPv6.dst",
    128,
    Mo::Msb,
    Cda::Lsb,
    LINK_LOCAL_PREFIX_TV,
    Some(64),
    None,
);

// Global address fields
const FD_IPV6_SRC_GLOBAL: FieldDescriptor = FieldDescriptor::new(
    "IPv6.src",
    128,
    Mo::Msb,
    Cda::Lsb,
    GLOBAL_PREFIX_TV,
    Some(8),
    None,
);
const FD_IPV6_DST_GLOBAL: FieldDescriptor = FieldDescriptor::new(
    "IPv6.dst",
    128,
    Mo::Msb,
    Cda::Lsb,
    GLOBAL_PREFIX_TV,
    Some(8),
    None,
);

// Next header fields
const FD_NEXT_UDP: FieldDescriptor = FieldDescriptor::new(
    "IPv6.next_header",
    8,
    Mo::Equal,
    Cda::NotSent,
    17,
    None,
    None,
);
const FD_NEXT_ICMPV6: FieldDescriptor = FieldDescriptor::new(
    "IPv6.next_header",
    8,
    Mo::Equal,
    Cda::NotSent,
    58,
    None,
    None,
);

// UDP fields
const FD_UDP_SRC_PORT: FieldDescriptor =
    FieldDescriptor::new("UDP.src_port", 16, Mo::Msb, Cda::Lsb, 5683, Some(12), None);
const FD_UDP_DST_PORT: FieldDescriptor =
    FieldDescriptor::new("UDP.dst_port", 16, Mo::Msb, Cda::Lsb, 5683, Some(12), None);
const FD_UDP_LENGTH: FieldDescriptor =
    FieldDescriptor::new("UDP.length", 16, Mo::Ignore, Cda::Compute, 0, None, None);
const FD_UDP_CHECKSUM: FieldDescriptor =
    FieldDescriptor::new("UDP.checksum", 16, Mo::Ignore, Cda::Compute, 0, None, None);

// CoAP fields
const FD_COAP_VERSION: FieldDescriptor =
    FieldDescriptor::new("CoAP.version", 2, Mo::Equal, Cda::NotSent, 1, None, None);
const FD_COAP_TYPE: FieldDescriptor =
    FieldDescriptor::new("CoAP.type", 2, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_COAP_TKL: FieldDescriptor =
    FieldDescriptor::new("CoAP.tkl", 4, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_COAP_CODE: FieldDescriptor =
    FieldDescriptor::new("CoAP.code", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_COAP_MID: FieldDescriptor =
    FieldDescriptor::new("CoAP.mid", 16, Mo::Ignore, Cda::ValueSent, 0, None, None);

// ICMPv6 Echo fields
const FD_ICMPV6_TYPE: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.type", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_ICMPV6_CODE_ZERO: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.code", 8, Mo::Equal, Cda::NotSent, 0, None, None);
const FD_ICMPV6_CHECKSUM: FieldDescriptor = FieldDescriptor::new(
    "ICMPv6.checksum",
    16,
    Mo::Ignore,
    Cda::Compute,
    0,
    None,
    None,
);
const FD_ICMPV6_IDENTIFIER: FieldDescriptor = FieldDescriptor::new(
    "ICMPv6.identifier",
    16,
    Mo::Ignore,
    Cda::ValueSent,
    0,
    None,
    None,
);
const FD_ICMPV6_SEQUENCE: FieldDescriptor = FieldDescriptor::new(
    "ICMPv6.sequence",
    16,
    Mo::Ignore,
    Cda::ValueSent,
    0,
    None,
    None,
);

// ICMPv6 RPL base fields
const FD_ICMPV6_RPL_TYPE: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.type", 8, Mo::Equal, Cda::NotSent, 155, None, None);
const FD_ICMPV6_CODE_DIO: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.code", 8, Mo::Equal, Cda::NotSent, 1, None, None);
const FD_ICMPV6_CODE_DAO: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.code", 8, Mo::Equal, Cda::NotSent, 2, None, None);

// RPL DIO fields
const FD_RPL_INSTANCE: FieldDescriptor =
    FieldDescriptor::new("RPL.instance", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_RPL_VERSION: FieldDescriptor =
    FieldDescriptor::new("RPL.version", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_RPL_RANK: FieldDescriptor =
    FieldDescriptor::new("RPL.rank", 16, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_RPL_GMOP: FieldDescriptor =
    FieldDescriptor::new("RPL.gmop", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_RPL_DTSN: FieldDescriptor =
    FieldDescriptor::new("RPL.dtsn", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_RPL_FLAGS: FieldDescriptor =
    FieldDescriptor::new("RPL.flags", 8, Mo::Equal, Cda::NotSent, 0, None, None);
const FD_RPL_RESERVED: FieldDescriptor =
    FieldDescriptor::new("RPL.reserved", 8, Mo::Equal, Cda::NotSent, 0, None, None);
const FD_RPL_DODAGID: FieldDescriptor = FieldDescriptor::new(
    "RPL.dodagid",
    128,
    Mo::Ignore,
    Cda::ValueSent,
    0,
    None,
    None,
);

// RPL DAO fields
const FD_RPL_KD_FLAGS: FieldDescriptor =
    FieldDescriptor::new("RPL.kd_flags", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_RPL_SEQ: FieldDescriptor =
    FieldDescriptor::new("RPL.seq", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);

// ---------------------------------------------------------------------------
// Rule field arrays
// ---------------------------------------------------------------------------

const LINK_LOCAL_COAP_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_UDP,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_LL,
    FD_IPV6_DST_LL,
    FD_UDP_SRC_PORT,
    FD_UDP_DST_PORT,
    FD_UDP_LENGTH,
    FD_UDP_CHECKSUM,
    FD_COAP_VERSION,
    FD_COAP_TYPE,
    FD_COAP_TKL,
    FD_COAP_CODE,
    FD_COAP_MID,
];

const GLOBAL_COAP_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_UDP,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_GLOBAL,
    FD_IPV6_DST_GLOBAL,
    FD_UDP_SRC_PORT,
    FD_UDP_DST_PORT,
    FD_UDP_LENGTH,
    FD_UDP_CHECKSUM,
    FD_COAP_VERSION,
    FD_COAP_TYPE,
    FD_COAP_TKL,
    FD_COAP_CODE,
    FD_COAP_MID,
];

const ICMPV6_ECHO_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_ICMPV6,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_LL,
    FD_IPV6_DST_LL,
    FD_ICMPV6_TYPE,
    FD_ICMPV6_CODE_ZERO,
    FD_ICMPV6_CHECKSUM,
    FD_ICMPV6_IDENTIFIER,
    FD_ICMPV6_SEQUENCE,
];

const RPL_DIO_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_ICMPV6,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_LL,
    FD_IPV6_DST_LL,
    FD_ICMPV6_RPL_TYPE,
    FD_ICMPV6_CODE_DIO,
    FD_ICMPV6_CHECKSUM,
    FD_RPL_INSTANCE,
    FD_RPL_VERSION,
    FD_RPL_RANK,
    FD_RPL_GMOP,
    FD_RPL_DTSN,
    FD_RPL_FLAGS,
    FD_RPL_RESERVED,
    FD_RPL_DODAGID,
];

const RPL_DAO_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_ICMPV6,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_LL,
    FD_IPV6_DST_LL,
    FD_ICMPV6_RPL_TYPE,
    FD_ICMPV6_CODE_DAO,
    FD_ICMPV6_CHECKSUM,
    FD_RPL_INSTANCE,
    FD_RPL_KD_FLAGS,
    FD_RPL_RESERVED,
    FD_RPL_SEQ,
    FD_RPL_DODAGID,
];

const LINK_LOCAL_OSCORE_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_UDP,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_LL,
    FD_IPV6_DST_LL,
    FD_UDP_SRC_PORT,
    FD_UDP_DST_PORT,
    FD_UDP_LENGTH,
    FD_UDP_CHECKSUM,
    FD_COAP_VERSION,
    FD_COAP_TYPE,
    FD_COAP_TKL,
    FD_COAP_CODE,
    FD_COAP_MID,
];

const GLOBAL_OSCORE_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_UDP,
    FD_IPV6_HOP_LIMIT,
    FD_IPV6_SRC_GLOBAL,
    FD_IPV6_DST_GLOBAL,
    FD_UDP_SRC_PORT,
    FD_UDP_DST_PORT,
    FD_UDP_LENGTH,
    FD_UDP_CHECKSUM,
    FD_COAP_VERSION,
    FD_COAP_TYPE,
    FD_COAP_TKL,
    FD_COAP_CODE,
    FD_COAP_MID,
];

const UNCOMPRESSED_FIELDS: &[FieldDescriptor] = &[];

// ---------------------------------------------------------------------------
// Public rule constants
// ---------------------------------------------------------------------------

pub const LINK_LOCAL_COAP_RULE: Rule = Rule::new(RULE_LINK_LOCAL_COAP, LINK_LOCAL_COAP_FIELDS);
pub const GLOBAL_COAP_RULE: Rule = Rule::new(RULE_GLOBAL_COAP, GLOBAL_COAP_FIELDS);
pub const ICMPV6_ECHO_RULE: Rule = Rule::new(RULE_ICMPV6_ECHO, ICMPV6_ECHO_FIELDS);
pub const RPL_DIO_RULE: Rule = Rule::new(RULE_RPL_DIO, RPL_DIO_FIELDS);
pub const RPL_DAO_RULE: Rule = Rule::new(RULE_RPL_DAO, RPL_DAO_FIELDS);
pub const LINK_LOCAL_OSCORE_RULE: Rule =
    Rule::new(RULE_LINK_LOCAL_OSCORE, LINK_LOCAL_OSCORE_FIELDS);
pub const GLOBAL_OSCORE_RULE: Rule = Rule::new(RULE_GLOBAL_OSCORE, GLOBAL_OSCORE_FIELDS);
pub const UNCOMPRESSED_RULE: Rule = Rule::new(RULE_UNCOMPRESSED, UNCOMPRESSED_FIELDS);

/// Immutable generic registry for Rule Set Version 3. Specialized Rule 7 is
/// intentionally absent: `codec::compress`/`codec::decompress` are its sole
/// byte-level implementation.
pub const RULE_SET_V3: &[Rule] = &[
    // OSCORE rules precede descriptor-identical plaintext rules so generic
    // selection has the same deterministic order as the whole-packet codecs.
    LINK_LOCAL_OSCORE_RULE,
    GLOBAL_OSCORE_RULE,
    LINK_LOCAL_COAP_RULE,
    GLOBAL_COAP_RULE,
    ICMPV6_ECHO_RULE,
    RPL_DIO_RULE,
    RPL_DAO_RULE,
    UNCOMPRESSED_RULE,
];

const FNV1A64_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV1A64_PRIME: u64 = 0x0000_0100_0000_01b3;

fn fingerprint_bytes(mut hash: u64, bytes: &[u8]) -> u64 {
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV1A64_PRIME);
    }
    hash
}

fn mo_fingerprint_code(mo: Mo) -> u8 {
    match mo {
        Mo::Equal => 0,
        Mo::Msb => 1,
        Mo::MatchMapping => 2,
        Mo::Ignore => 3,
        _ => u8::MAX,
    }
}

fn cda_fingerprint_code(cda: Cda) -> u8 {
    match cda {
        Cda::NotSent => 0,
        Cda::ValueSent => 1,
        Cda::Lsb => 2,
        Cda::Compute => 3,
        Cda::MappingSent => 4,
        _ => u8::MAX,
    }
}

/// Return the canonical Version 3 registry descriptor fingerprint.
///
/// The FNV-1a-64 byte stream is domain-separated with
/// `LICHEN-SCHC-DESC-v1`, then encodes the registry version, ordered rules,
/// and every descriptor field in fixed-width network byte order. This is an
/// interoperability fingerprint, not a cryptographic integrity primitive.
pub fn rule_set_v3_descriptor_hash() -> u64 {
    let mut hash = fingerprint_bytes(FNV1A64_OFFSET, b"LICHEN-SCHC-DESC-v1\0");
    hash = fingerprint_bytes(hash, &[RULE_SET_VERSION]);
    for rule in RULE_SET_V3 {
        hash = fingerprint_bytes(hash, &[b'R', rule.rule_id]);
        hash = fingerprint_bytes(hash, &(rule.fields.len() as u16).to_be_bytes());
        for descriptor in rule.fields {
            let field_id = descriptor.field_id.as_bytes();
            hash = fingerprint_bytes(hash, &(field_id.len() as u16).to_be_bytes());
            hash = fingerprint_bytes(hash, field_id);
            hash = fingerprint_bytes(hash, &descriptor.length_bits.to_be_bytes());
            hash = fingerprint_bytes(
                hash,
                &[
                    mo_fingerprint_code(descriptor.mo),
                    cda_fingerprint_code(descriptor.cda),
                ],
            );
            hash = fingerprint_bytes(hash, &descriptor.target_value.to_be_bytes());
            hash = fingerprint_bytes(hash, &descriptor.mo_arg.unwrap_or(u16::MAX).to_be_bytes());
            let mapping = descriptor.mapping.unwrap_or(&[]);
            hash = fingerprint_bytes(hash, &(mapping.len() as u16).to_be_bytes());
            for value in mapping {
                hash = fingerprint_bytes(hash, &value.to_be_bytes());
            }
        }
    }
    hash
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_three_registry_has_canonical_membership_and_order() {
        let expected = [5, 6, 0, 1, 2, 3, 4, 255];
        assert_eq!(RULE_SET_V3.len(), expected.len());
        assert!(RULE_SET_V3
            .iter()
            .zip(expected)
            .all(|(rule, expected_id)| rule.rule_id == expected_id));
        assert!(RULE_SET_V3
            .iter()
            .all(|rule| !matches!(rule.rule_id, 64..=66)));
    }

    #[test]
    fn rule_version_option_current() {
        let opt = SchcRuleVersionOption::current();
        assert_eq!(opt.version, RULE_SET_VERSION);
        assert_eq!(opt.version, 3);
        assert!(opt.is_current());
    }

    #[test]
    fn rule_version_option_to_bytes() {
        let opt = SchcRuleVersionOption::new(3);
        let bytes = opt.to_bytes();
        assert_eq!(bytes, [0x13, 1, 3]);
    }

    #[test]
    fn rule_version_option_from_bytes() {
        let bytes = [0x13, 1, 3];
        let opt = SchcRuleVersionOption::from_bytes(&bytes).unwrap();
        assert_eq!(opt.version, 3);
        assert!(opt.is_current());
    }

    #[test]
    fn rule_version_option_roundtrip() {
        let original = SchcRuleVersionOption::new(42);
        let bytes = original.to_bytes();
        let parsed = SchcRuleVersionOption::from_bytes(&bytes).unwrap();
        assert_eq!(original, parsed);
    }

    #[test]
    fn rule_version_option_from_bytes_wrong_type() {
        let bytes = [0x14, 1, 2]; // Wrong type
        assert!(SchcRuleVersionOption::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rule_version_option_from_bytes_wrong_length() {
        let bytes = [0x13, 2, 2]; // Wrong length field
        assert!(SchcRuleVersionOption::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rule_version_option_from_bytes_too_short() {
        let bytes = [0x13, 1]; // Missing version byte
        assert!(SchcRuleVersionOption::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rule_version_option_from_bytes_rejects_trailing_bytes() {
        assert!(SchcRuleVersionOption::from_bytes(&[0x13, 1, 3, 0xff]).is_none());
    }

    #[test]
    fn only_version_three_has_a_local_registry() {
        assert_eq!(
            SchcRuleVersionOption::local(3),
            Some(SchcRuleVersionOption::current())
        );
        assert!(SchcRuleVersionOption::local(0).is_none());
        assert!(SchcRuleVersionOption::local(2).is_none());
        assert!(SchcRuleVersionOption::local(255).is_none());
        assert!(versions_compatible(3, 3));
        assert!(!versions_compatible(2, 2));
    }

    #[test]
    fn rule_version_option_is_not_current() {
        let opt = SchcRuleVersionOption::new(1); // Legacy version
        assert!(!opt.is_current());
    }
}
