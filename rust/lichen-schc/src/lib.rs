//! SCHC header compression for LICHEN (RFC 8724).
//!
//! Provides the rule model (`Rule`, `FieldDescriptor`, `Mo`, `Cda`) and
//! compress/decompress stubs. The five whole-packet rules 0-4 match the
//! Python reference in `python/src/lichen/schc/rules.py`; rule 255 is the
//! uncompressed fallback.
//!
//! Rule IDs match `constants.toml` [schc.rule_id]:
//! - 0  link-local IPv6 + UDP + CoAP
//! - 1  global IPv6 + UDP + CoAP
//! - 2  ICMPv6 Echo (link-local)
//! - 3  RPL DIO (link-local ICMPv6)
//! - 4  RPL DAO (routable ULA source for multi-hop)
//! - 255 uncompressed passthrough

#![no_std]

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
