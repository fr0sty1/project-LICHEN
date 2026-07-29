//! SCHC header compression for LICHEN (RFC 8724).
//!
//! This crate is a thin wrapper around the `schc` crate, adding LICHEN-specific
//! compression rules. The core SCHC types are re-exported from the `schc` crate.
//!
//! Rule IDs match `constants.toml` [schc.rule_id]:
//! - 0  link-local IPv6 + UDP + CoAP
//! - 1  global IPv6 + UDP + CoAP
//! - 2  ICMPv6 Echo (link-local)
//! - 3  RPL DIO (link-local ICMPv6)
//! - 4  RPL DAO (link-local ICMPv6)
//! - 5  link-local IPv6 + UDP + OSCORE CoAP
//! - 6  global IPv6 + UDP + OSCORE CoAP
//! - 255 uncompressed passthrough

#![no_std]
#![forbid(unsafe_code)]

// Re-export core SCHC types from the schc crate
pub use schc::compress::{Cda, FieldDescriptor, Mo, Rule};

// LICHEN-specific modules
pub mod codec;
pub mod context;
pub mod fragment;
pub mod headers;
pub mod rules;

// Re-export LICHEN-specific compression/decompression
pub use codec::{compress, decompress, SchcError};
pub use context::{rule_matches, FieldId, NoMatchingRuleError, SchcContext};
pub use headers::{
    CoapUdpGlobalProfile, CoapUdpLinkLocalProfile, Icmpv6EchoProfile, PacketError, PacketProfile,
    ParsedPacket, RplDaoProfile, RplDioProfile, DEFAULT_PROFILES, MAX_FIELDS,
};

// Re-export LICHEN-specific rule constants
pub use rules::{
    GLOBAL_COAP_RULE, GLOBAL_OSCORE_RULE, ICMPV6_ECHO_RULE, LINK_LOCAL_COAP_RULE,
    LINK_LOCAL_OSCORE_RULE, MQTT_SN_RULE, RPL_DAO_RULE, RPL_DIO_RULE, UNCOMPRESSED_RULE,
};

#[cfg(feature = "std")]
extern crate std;
