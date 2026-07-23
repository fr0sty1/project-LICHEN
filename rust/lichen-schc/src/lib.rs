//! SCHC header compression for LICHEN (RFC 8724).
//!
//! Provides the rule model (`Rule`, `FieldDescriptor`, `Mo`, `Cda`) and
//! compress/decompress stubs. Rules 0-6 match the Python reference in
//! `python/src/lichen/schc/rules.py` (incl. OSCORE 5/6); rule 255 is uncompressed.
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

pub mod codec;
pub mod context;
pub mod fragment;
pub mod headers;
pub mod rules;

pub use codec::{compress, decompress, SchcError};
pub use context::{rule_matches, FieldId, NoMatchingRuleError, SchcContext};
pub use headers::{
    CoapUdpGlobalProfile, CoapUdpLinkLocalProfile, Icmpv6EchoProfile, PacketError, PacketProfile,
    ParsedPacket, RplDaoProfile, RplDioProfile, DEFAULT_PROFILES, MAX_FIELDS,
};
pub use rules::{Cda, FieldDescriptor, Mo, Rule};

#[cfg(feature = "std")]
extern crate std;
