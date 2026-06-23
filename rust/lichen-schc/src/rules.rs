//! SCHC rule model (RFC 8724 §7).

use lichen_core::constants::{
    RULE_GLOBAL_COAP, RULE_ICMPV6_ECHO, RULE_LINK_LOCAL_COAP,
    RULE_RPL_DAO, RULE_RPL_DIO, RULE_UNCOMPRESSED,
};

/// Matching Operator — decides whether a rule applies to a field value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mo {
    Equal,
    Ignore,
    Msb,
    MatchMapping,
}

/// Compression/Decompression Action — what appears in the residue.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Cda {
    NotSent,
    ValueSent,
    Lsb,
    Compute,
    MappingSent,
}

/// One field's compression behaviour within a rule (RFC 8724 §7.4).
#[derive(Clone, Debug)]
pub struct FieldDescriptor {
    /// Stable identifier, e.g. `"CoAP.MID"`.
    pub field_id: &'static str,
    /// Field width in bits.
    pub length_bits: u16,
    pub mo: Mo,
    pub cda: Cda,
    /// Target value for Equal/MSB matching and NotSent reconstruction.
    pub target_value: u128,
    /// For MSB: number of most-significant bits to match; also determines
    /// residue width (`length_bits - mo_arg`).
    pub mo_arg: Option<u16>,
}

/// A SCHC rule: an ordered list of field descriptors keyed by a rule ID.
///
/// Rule IDs 0-127 are compression rules; 255 is the uncompressed fallback.
pub struct Rule {
    pub rule_id: u8,
    pub fields: &'static [FieldDescriptor],
}

// ---------------------------------------------------------------------------
// Whole-packet rule registry — empty slices until the full rule tables are
// populated in a future implementation pass.
// ---------------------------------------------------------------------------

pub const LINK_LOCAL_COAP_RULE: Rule = Rule { rule_id: RULE_LINK_LOCAL_COAP, fields: &[] };
pub const GLOBAL_COAP_RULE: Rule = Rule { rule_id: RULE_GLOBAL_COAP, fields: &[] };
pub const ICMPV6_ECHO_RULE: Rule = Rule { rule_id: RULE_ICMPV6_ECHO, fields: &[] };
pub const RPL_DIO_RULE: Rule = Rule { rule_id: RULE_RPL_DIO, fields: &[] };
pub const RPL_DAO_RULE: Rule = Rule { rule_id: RULE_RPL_DAO, fields: &[] };
pub const UNCOMPRESSED_RULE: Rule = Rule { rule_id: RULE_UNCOMPRESSED, fields: &[] };
