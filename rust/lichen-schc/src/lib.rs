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
//! - 4  RPL DAO (link-local ICMPv6)
//! - 255 uncompressed passthrough

#![no_std]

pub mod rules;
pub mod codec;

pub use rules::{Cda, FieldDescriptor, Mo, Rule};

#[cfg(feature = "std")]
extern crate std;
