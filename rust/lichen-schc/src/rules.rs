//! LICHEN-specific SCHC rules (RFC 8724 Section 7).
//!
//! This module defines the compression rules specific to the LICHEN protocol.
//! The core types (Mo, Cda, FieldDescriptor, Rule) are re-exported from the
//! `schc` crate at the crate root.

use lichen_core::constants::{
    RULE_GLOBAL_COAP, RULE_GLOBAL_OSCORE, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP,
    RULE_LINK_LOCAL_OSCORE, RULE_MQTT_SN, RULE_RPL_DAO, RULE_RPL_DIO, RULE_UNCOMPRESSED,
};

// Import types from the schc crate
use schc::compress::{Cda, FieldDescriptor, Mo, Rule};

// ---------------------------------------------------------------------------
const LINK_LOCAL_PREFIX_TV: u128 = 0xfe80_0000_0000_0000_0000_0000_0000_0000;
const GLOBAL_PREFIX_TV: u128 = 0xfd00_0000_0000_0000_0000_0000_0000_0000;

// ---------------------------------------------------------------------------
// Individual field descriptors for reuse across rules
// ---------------------------------------------------------------------------

// IPv6 base fields
const FD_IPV6_VERSION: FieldDescriptor =
    FieldDescriptor::new("IPv6.version", 4, Mo::Equal, Cda::NotSent, 6, None, None);
const FD_IPV6_TRAFFIC_CLASS: FieldDescriptor =
    FieldDescriptor::new("IPv6.traffic_class", 8, Mo::Equal, Cda::NotSent, 0, None, None);
const FD_IPV6_FLOW_LABEL: FieldDescriptor =
    FieldDescriptor::new("IPv6.flow_label", 20, Mo::Equal, Cda::NotSent, 0, None, None);
const FD_IPV6_PAYLOAD_LENGTH: FieldDescriptor =
    FieldDescriptor::new("IPv6.payload_length", 16, Mo::Ignore, Cda::Compute, 0, None, None);
const FD_IPV6_HOP_LIMIT: FieldDescriptor =
    FieldDescriptor::new("IPv6.hop_limit", 8, Mo::Ignore, Cda::ValueSent, 0, None, None);

// Link-local address fields
const FD_IPV6_SRC_LL: FieldDescriptor =
    FieldDescriptor::new("IPv6.src", 128, Mo::Msb, Cda::Lsb, LINK_LOCAL_PREFIX_TV, Some(64), None);
const FD_IPV6_DST_LL: FieldDescriptor =
    FieldDescriptor::new("IPv6.dst", 128, Mo::Msb, Cda::Lsb, LINK_LOCAL_PREFIX_TV, Some(64), None);

// Global address fields
const FD_IPV6_SRC_GLOBAL: FieldDescriptor =
    FieldDescriptor::new("IPv6.src", 128, Mo::Msb, Cda::Lsb, GLOBAL_PREFIX_TV, Some(64), None);
const FD_IPV6_DST_GLOBAL: FieldDescriptor =
    FieldDescriptor::new("IPv6.dst", 128, Mo::Msb, Cda::Lsb, GLOBAL_PREFIX_TV, Some(64), None);

// Next header fields
const FD_NEXT_UDP: FieldDescriptor =
    FieldDescriptor::new("IPv6.next_header", 8, Mo::Equal, Cda::NotSent, 17, None, None);
const FD_NEXT_ICMPV6: FieldDescriptor =
    FieldDescriptor::new("IPv6.next_header", 8, Mo::Equal, Cda::NotSent, 58, None, None);

// UDP fields
const FD_UDP_SRC_PORT: FieldDescriptor =
    FieldDescriptor::new("UDP.src_port", 16, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_UDP_DST_PORT: FieldDescriptor =
    FieldDescriptor::new("UDP.dst_port", 16, Mo::Ignore, Cda::ValueSent, 0, None, None);
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
const FD_ICMPV6_CHECKSUM: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.checksum", 16, Mo::Ignore, Cda::Compute, 0, None, None);
const FD_ICMPV6_IDENTIFIER: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.identifier", 16, Mo::Ignore, Cda::ValueSent, 0, None, None);
const FD_ICMPV6_SEQUENCE: FieldDescriptor =
    FieldDescriptor::new("ICMPv6.sequence", 16, Mo::Ignore, Cda::ValueSent, 0, None, None);

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
const FD_RPL_DODAGID: FieldDescriptor =
    FieldDescriptor::new("RPL.dodagid", 128, Mo::Ignore, Cda::ValueSent, 0, None, None);

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

const MQTT_SN_FIELDS: &[FieldDescriptor] = &[
    FD_IPV6_VERSION,
    FD_IPV6_TRAFFIC_CLASS,
    FD_IPV6_FLOW_LABEL,
    FD_IPV6_PAYLOAD_LENGTH,
    FD_NEXT_UDP,
    FD_IPV6_HOP_LIMIT,
    // use global (Ignore) to support both link-local and global addresses in one rule
    FD_IPV6_SRC_GLOBAL,
    FD_IPV6_DST_GLOBAL,
    FD_UDP_SRC_PORT,
    FD_UDP_DST_PORT,
    FD_UDP_LENGTH,
    FD_UDP_CHECKSUM,
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
pub const LINK_LOCAL_OSCORE_RULE: Rule = Rule::new(RULE_LINK_LOCAL_OSCORE, LINK_LOCAL_OSCORE_FIELDS);
pub const GLOBAL_OSCORE_RULE: Rule = Rule::new(RULE_GLOBAL_OSCORE, GLOBAL_OSCORE_FIELDS);
pub const MQTT_SN_RULE: Rule = Rule::new(RULE_MQTT_SN, MQTT_SN_FIELDS);
pub const UNCOMPRESSED_RULE: Rule = Rule::new(RULE_UNCOMPRESSED, UNCOMPRESSED_FIELDS);
