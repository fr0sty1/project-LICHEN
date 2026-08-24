//! SCHC rule context and selection (RFC 8724 section 7).
//!
//! A [`SchcContext`] holds the active rule set and selects a matching rule for
//! a set of field values: the first rule (by ascending rule ID) whose every
//! descriptor is satisfied -- EQUAL/MSB constraints hold and all fields needed
//! for the residue are present. If no compression rule matches, selection falls
//! back to the uncompressed rule (ID 255).
//!
//! This mirrors the Python `lichen.schc.context` module.

use crate::rules::UNCOMPRESSED_RULE;
use lichen_core::constants::{RULE_GLOBAL_OSCORE, RULE_LINK_LOCAL_OSCORE};
use schc::compress::{Cda, FieldDescriptor, Mo, Rule};

/// Error returned when no rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoMatchingRuleError;

impl core::fmt::Display for NoMatchingRuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "no SCHC rule matches the given fields")
    }
}

impl core::error::Error for NoMatchingRuleError {}

/// Error returned when a bounded failure tracker has no slot for a new source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FailureTrackerFull;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FailureEntry {
    source: [u8; 32],
    count: u16,
    notified: bool,
}

/// Bounded per-signer tracker for repeated SCHC decompression failures.
///
/// [`record_failure`](Self::record_failure) reports `true` exactly once when a
/// source reaches the configured consecutive-failure threshold. A successful
/// decompression clears the source and permits a later run to notify again.
pub struct RuleVersionFailureTracker<const MAX_SOURCES: usize> {
    threshold: u16,
    entries: [Option<FailureEntry>; MAX_SOURCES],
    capacity_events: u64,
}

impl<const MAX_SOURCES: usize> RuleVersionFailureTracker<MAX_SOURCES> {
    /// Construct a bounded tracker. Zero threshold or capacity is invalid.
    pub fn new(threshold: u16) -> Option<Self> {
        if threshold == 0 || MAX_SOURCES == 0 {
            return None;
        }
        Some(Self {
            threshold,
            entries: [None; MAX_SOURCES],
            capacity_events: 0,
        })
    }

    /// Record one failure and report a newly crossed notification threshold.
    pub fn record_failure(&mut self, source: [u8; 32]) -> Result<bool, FailureTrackerFull> {
        if let Some(entry) = self
            .entries
            .iter_mut()
            .flatten()
            .find(|entry| entry.source == source)
        {
            entry.count = entry.count.saturating_add(1).min(self.threshold);
            let notify = entry.count == self.threshold && !entry.notified;
            entry.notified |= notify;
            return Ok(notify);
        }
        let Some(slot) = self.entries.iter_mut().find(|entry| entry.is_none()) else {
            self.capacity_events = self.capacity_events.saturating_add(1);
            return Err(FailureTrackerFull);
        };
        let notify = self.threshold == 1;
        *slot = Some(FailureEntry {
            source,
            count: 1,
            notified: notify,
        });
        Ok(notify)
    }

    /// Clear consecutive failures after a successful decompression.
    pub fn record_success(&mut self, source: &[u8; 32]) {
        if let Some(slot) = self
            .entries
            .iter_mut()
            .find(|entry| entry.is_some_and(|entry| &entry.source == source))
        {
            *slot = None;
        }
    }

    /// Retire tracking state when the owning link retires/evicts this signer.
    pub fn retire(&mut self, source: &[u8; 32]) {
        self.record_success(source);
    }

    /// Number of failures that could not be assigned a bounded source slot.
    pub const fn capacity_events(&self) -> u64 {
        self.capacity_events
    }
}

/// Check whether a field descriptor requires a value to be present in the fields dict.
///
/// A field requires a value if:
/// - CDA is ValueSent, Lsb, or MappingSent (field contributes to residue)
/// - MO is Equal, Msb, or MatchMapping (field participates in matching)
pub fn field_requires_value(fd: &FieldDescriptor) -> bool {
    // If CDA sends data, we need the value
    if matches!(fd.cda, Cda::ValueSent | Cda::Lsb | Cda::MappingSent) {
        return true;
    }
    // If MO matches against the field, we need the value
    matches!(fd.mo, Mo::Equal | Mo::Msb | Mo::MatchMapping)
}

/// Return whether `value` can be represented by a field of `length_bits`.
///
/// The explicit 128-bit case avoids shifting a `u128` by its type width.
fn value_fits_width(value: u128, length_bits: u16) -> bool {
    match length_bits {
        1..=127 => value < (1u128 << length_bits),
        128 => true,
        _ => false,
    }
}

/// Validate descriptor widths and all width-constrained descriptor values.
fn descriptor_values_fit(fd: &FieldDescriptor) -> bool {
    if !(1..=u128::BITS as u16).contains(&fd.length_bits) {
        return false;
    }

    // Keep admission fail-closed: schc's enums are non-exhaustive and a future
    // MO/CDA variant or an unsupported pairing must not silently become
    // selectable before LICHEN defines its reconstruction semantics.
    if !supported_mo_cda_pair(fd.mo, fd.cda) {
        return false;
    }

    // Rule values are canonical field values even when a particular CDA does
    // not consume the target directly. Rejecting out-of-width targets keeps
    // Rust rule admission aligned with the Python implementation.
    if !value_fits_width(fd.target_value, fd.length_bits) {
        return false;
    }

    match (fd.mo, fd.mo_arg) {
        (Mo::Msb, Some(mo_arg)) if mo_arg <= fd.length_bits => {}
        (Mo::Msb, _) | (_, Some(_)) => return false,
        _ => {}
    }

    match (fd.mo, fd.mapping) {
        (Mo::MatchMapping, Some(mapping)) => {
            if mapping.len() < 2
                || !mapping
                    .iter()
                    .all(|&value| value_fits_width(value, fd.length_bits))
                || mapping
                    .iter()
                    .enumerate()
                    .any(|(index, value)| mapping[..index].contains(value))
            {
                return false;
            }
        }
        (Mo::MatchMapping, None) | (_, Some(_)) => return false,
        _ => {}
    }

    true
}

/// Return whether LICHEN defines lossless semantics for this MO/CDA pair.
fn supported_mo_cda_pair(mo: Mo, cda: Cda) -> bool {
    matches!(
        (mo, cda),
        (Mo::Equal, Cda::NotSent)
            | (Mo::Equal, Cda::ValueSent)
            | (Mo::Equal, Cda::Compute)
            | (Mo::Msb, Cda::Lsb)
            | (Mo::Msb, Cda::ValueSent)
            | (Mo::Msb, Cda::Compute)
            | (Mo::MatchMapping, Cda::MappingSent)
            | (Mo::MatchMapping, Cda::ValueSent)
            | (Mo::MatchMapping, Cda::Compute)
            | (Mo::Ignore, Cda::ValueSent)
            | (Mo::Ignore, Cda::Compute)
    )
}

/// Return whether every descriptor in a rule is valid for this context.
fn rule_is_supported(rule: &Rule) -> bool {
    rule.fields.iter().all(descriptor_values_fit)
}

/// Whether `fields` satisfy every descriptor of `rule`.
///
/// Returns true if all descriptors match:
/// - For `Mo::Equal`: field value must equal target_value
/// - For `Mo::Msb`: the most-significant `mo_arg` bits must match
/// - For `Mo::MatchMapping`: value must be in the mapping table from rule
/// - For `Mo::Ignore`: always matches (field may or may not be present)
pub fn rule_matches(rule: &Rule, fields: &[(FieldId, u128)]) -> bool {
    for fd in rule.fields {
        if !descriptor_values_fit(fd) {
            return false;
        }

        let value = find_field(fields, fd.field_id);

        match value {
            None => {
                // Field not present -- allowed only if not required
                if field_requires_value(fd) {
                    return false;
                }
            }
            Some(val) => {
                if !value_fits_width(val, fd.length_bits) {
                    return false;
                }

                match fd.mo {
                    Mo::Equal => {
                        if val != fd.target_value {
                            return false;
                        }
                    }
                    Mo::Msb => {
                        if let Some(mo_arg) = fd.mo_arg {
                            // Width and representability were validated above. A zero-bit
                            // prefix is a wildcard; every non-zero valid prefix leaves a
                            // shift in 0..=127 for the u128 field value.
                            if mo_arg > fd.length_bits {
                                return false; // invalid mo_arg, rule cannot match
                            }
                            if mo_arg == 0 {
                                continue;
                            }
                            let shift = fd.length_bits - mo_arg;
                            if (val >> shift) != (fd.target_value >> shift) {
                                return false;
                            }
                        } else {
                            return false; // MSB without mo_arg is invalid
                        }
                    }
                    Mo::MatchMapping => {
                        if let Some(mapping) = fd.mapping {
                            if !mapping.contains(&val) {
                                return false;
                            }
                        } else {
                            return false;
                        }
                    }
                    Mo::Ignore => {
                        // Always matches, value is ignored
                    }
                    // Handle future Mo variants from schc crate
                    _ => return false,
                }
            }
        }
    }
    true
}

/// A field identifier (static string slice).
pub type FieldId = &'static str;

/// Look up a field by ID in a field list.
fn find_field(fields: &[(FieldId, u128)], id: &str) -> Option<u128> {
    for (field_id, value) in fields {
        if *field_id == id {
            return Some(*value);
        }
    }
    None
}

/// An ordered set of SCHC rules with pattern-based selection.
///
/// Rules are stored sorted by ascending rule ID for deterministic selection.
pub struct SchcContext<'a> {
    rules: &'a [Rule],
}

impl<'a> SchcContext<'a> {
    /// Create a context from a slice of rules.
    ///
    /// Rules should be sorted by ascending rule ID for deterministic behavior.
    pub const fn new(rules: &'a [Rule]) -> Self {
        Self { rules }
    }

    /// Look up a rule by ID.
    ///
    /// Malformed or unsupported rules are treated as absent so a received rule
    /// ID cannot bypass the same descriptor admission enforced for selection.
    pub fn get(&self, rule_id: u8) -> Option<&Rule> {
        self.rules
            .iter()
            .find(|rule| rule.rule_id == rule_id && rule_is_supported(rule))
    }

    /// Find the first matching compression rule, or None if none matches.
    ///
    /// Skips the uncompressed rule (ID 255) during selection.
    pub fn select_rule(&self, fields: &[(FieldId, u128)]) -> Option<&Rule> {
        for rule in self.rules {
            if rule.rule_id == UNCOMPRESSED_RULE.rule_id {
                continue;
            }
            if matches!(rule.rule_id, RULE_LINK_LOCAL_OSCORE | RULE_GLOBAL_OSCORE) {
                // OSCORE is a security assertion, not a header pattern. The
                // descriptor-identical rules may only be selected by the
                // explicit trusted path below.
                continue;
            }
            if rule_matches(rule, fields) {
                return Some(rule);
            }
        }
        None
    }

    /// Select an OSCORE rule after a trusted CoAP parser has authenticated the
    /// OSCORE option/protection context.
    pub fn select_oscore_rule(&self, fields: &[(FieldId, u128)]) -> Option<&Rule> {
        self.rules.iter().find(|rule| {
            matches!(rule.rule_id, RULE_LINK_LOCAL_OSCORE | RULE_GLOBAL_OSCORE)
                && rule_is_supported(rule)
                && rule_matches(rule, fields)
        })
    }

    /// Returns the number of rules in this context.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    /// Returns true if this context has no rules.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Returns an iterator over the rules.
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use self::std::boxed::Box;
    use super::*;
    use crate::rules::{
        GLOBAL_COAP_RULE, GLOBAL_OSCORE_RULE, ICMPV6_ECHO_RULE, LINK_LOCAL_COAP_RULE,
        LINK_LOCAL_OSCORE_RULE, RPL_DAO_RULE, RPL_DIO_RULE,
    };
    use schc::compress::{
        compress as generic_compress, decompress as generic_decompress, Cda, FieldDescriptor, Mo,
        Rule,
    };

    const KNOWN_MATCHING_OPERATORS: &[Mo] = &[Mo::Equal, Mo::Msb, Mo::MatchMapping, Mo::Ignore];
    const KNOWN_COMPRESSION_ACTIONS: &[Cda] = &[
        Cda::NotSent,
        Cda::ValueSent,
        Cda::Lsb,
        Cda::Compute,
        Cda::MappingSent,
    ];
    const VALID_MO_CDA_PAIRS: &[(Mo, Cda)] = &[
        (Mo::Equal, Cda::NotSent),
        (Mo::Equal, Cda::ValueSent),
        (Mo::Equal, Cda::Compute),
        (Mo::Msb, Cda::Lsb),
        (Mo::Msb, Cda::ValueSent),
        (Mo::Msb, Cda::Compute),
        (Mo::MatchMapping, Cda::MappingSent),
        (Mo::MatchMapping, Cda::ValueSent),
        (Mo::MatchMapping, Cda::Compute),
        (Mo::Ignore, Cda::ValueSent),
        (Mo::Ignore, Cda::Compute),
    ];
    const WIDTH_ONE_MAPPING: &[u128] = &[0, 1];
    const WIDTH_128_MAPPING: &[u128] = &[0, u128::MAX];
    const EMPTY_MAPPING: &[u128] = &[];
    const SINGLETON_MAPPING: &[u128] = &[1];
    const MULTI_MAPPING: &[u128] = &[0, 1];
    const DUPLICATE_MAPPING: &[u128] = &[1, 1];
    const DUPLICATE_WIDTH_128_MAPPING: &[u128] = &[u128::MAX, u128::MAX];
    const INVALID_WIDTH_ONE_MAPPING: &[u128] = &[0, 2];

    fn one_field_rule(fd: FieldDescriptor) -> Rule {
        Rule::new(100, Box::leak(Box::new([fd])))
    }

    fn descriptor_for(
        length_bits: u16,
        mo: Mo,
        cda: Cda,
        target_value: u128,
        mapping: Option<&'static [u128]>,
    ) -> FieldDescriptor {
        FieldDescriptor::new(
            "test.width",
            length_bits,
            mo,
            cda,
            target_value,
            matches!(mo, Mo::Msb).then_some(0),
            mapping,
        )
    }

    fn assert_generic_round_trip(fd: FieldDescriptor, value: u128, expected: u128) {
        let rule = one_field_rule(fd);
        let fields = [("test.width", value)];
        assert!(rule_matches(&rule, &fields));

        let mut residue = [0u8; 32];
        let residue_len = generic_compress(&rule, &[value], &mut residue).unwrap();
        let mut reconstructed = [0u128; 1];
        let (field_count, _) =
            generic_decompress(&rule, &residue[..residue_len], &mut reconstructed).unwrap();
        assert_eq!(field_count, 1);
        assert_eq!(reconstructed[0], expected);
    }

    // Test descriptors for a simple rule
    const TEST_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor::new("IPv6.version", 4, Mo::Equal, Cda::NotSent, 6, None, None),
        FieldDescriptor::new(
            "IPv6.hop_limit",
            8,
            Mo::Ignore,
            Cda::ValueSent,
            64,
            None,
            None,
        ),
    ];

    const TEST_RULE: Rule = Rule::new(0, TEST_FIELDS);

    const TEST_RULES: &[Rule] = &[TEST_RULE];

    #[test]
    fn rule_matches_equal_satisfied() {
        let fields: &[(FieldId, u128)] = &[("IPv6.version", 6), ("IPv6.hop_limit", 64)];
        assert!(rule_matches(&TEST_RULE, fields));
    }

    #[test]
    fn rule_matches_equal_not_satisfied() {
        let fields: &[(FieldId, u128)] = &[
            ("IPv6.version", 4), // Wrong version
            ("IPv6.hop_limit", 64),
        ];
        assert!(!rule_matches(&TEST_RULE, fields));
    }

    #[test]
    fn rule_matches_missing_required_field() {
        // hop_limit has CDA::ValueSent, so it's required
        let fields: &[(FieldId, u128)] = &[
            ("IPv6.version", 6),
            // Missing hop_limit
        ];
        assert!(!rule_matches(&TEST_RULE, fields));
    }

    #[test]
    fn context_select_rule() {
        let ctx = SchcContext::new(TEST_RULES);
        let fields: &[(FieldId, u128)] = &[("IPv6.version", 6), ("IPv6.hop_limit", 64)];
        let rule = ctx.select_rule(fields);
        assert!(rule.is_some());
        assert_eq!(rule.unwrap().rule_id, 0);
    }

    #[test]
    fn context_select_rule_no_match() {
        let ctx = SchcContext::new(TEST_RULES);
        let fields: &[(FieldId, u128)] = &[
            ("IPv6.version", 4), // Wrong version
            ("IPv6.hop_limit", 64),
        ];
        let rule = ctx.select_rule(fields);
        assert!(rule.is_none());
    }

    #[test]
    fn context_get_rule() {
        let ctx = SchcContext::new(TEST_RULES);
        assert!(ctx.get(0).is_some());
        assert!(ctx.get(99).is_none());
    }

    #[test]
    fn every_builtin_rule_passes_descriptor_admission() {
        for rule in [
            LINK_LOCAL_COAP_RULE,
            GLOBAL_COAP_RULE,
            ICMPV6_ECHO_RULE,
            RPL_DIO_RULE,
            RPL_DAO_RULE,
            LINK_LOCAL_OSCORE_RULE,
            GLOBAL_OSCORE_RULE,
            UNCOMPRESSED_RULE,
        ] {
            assert!(rule_is_supported(&rule), "rule {}", rule.rule_id);
        }
    }

    #[test]
    fn msb_matching() {
        // Test MSB matching operator
        const MSB_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "IPv6.src",
            128,
            Mo::Msb,
            Cda::Lsb,
            0xFE80_0000_0000_0000_0000_0000_0000_0000,
            Some(64), // Match first 64 bits
            None,
        )];
        const MSB_RULE: Rule = Rule::new(1, MSB_FIELDS);

        // Link-local address should match
        let fields: &[(FieldId, u128)] = &[("IPv6.src", 0xFE80_0000_0000_0000_1234_5678_9ABC_DEF0)];
        assert!(rule_matches(&MSB_RULE, fields));

        // Global address should not match
        let fields: &[(FieldId, u128)] = &[("IPv6.src", 0x2001_0DB8_0000_0000_1234_5678_9ABC_DEF0)];
        assert!(!rule_matches(&MSB_RULE, fields));
    }

    #[test]
    fn msb_matching_handles_full_width_boundaries() {
        const ZERO_PREFIX_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "IPv6.src",
            128,
            Mo::Msb,
            Cda::Lsb,
            u128::MAX,
            Some(0),
            None,
        )];
        const ONE_BIT_PREFIX_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "IPv6.src",
            128,
            Mo::Msb,
            Cda::Lsb,
            1 << 127,
            Some(1),
            None,
        )];
        const ONE_HUNDRED_TWENTY_SEVEN_PREFIX_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "IPv6.src",
            128,
            Mo::Msb,
            Cda::Lsb,
            u128::MAX,
            Some(127),
            None,
        )];
        const FULL_PREFIX_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "IPv6.src",
            128,
            Mo::Msb,
            Cda::Lsb,
            u128::MAX,
            Some(128),
            None,
        )];

        let zero_prefix_rule = Rule::new(2, ZERO_PREFIX_FIELDS);
        assert!(rule_matches(&zero_prefix_rule, &[("IPv6.src", 0)]));
        assert!(rule_matches(
            &zero_prefix_rule,
            &[("IPv6.src", 0x0123_4567_89AB_CDEF_FEDC_BA98_7654_3210)]
        ));

        let one_bit_prefix_rule = Rule::new(3, ONE_BIT_PREFIX_FIELDS);
        assert!(rule_matches(
            &one_bit_prefix_rule,
            &[("IPv6.src", (1 << 127) | 1)]
        ));
        assert!(!rule_matches(
            &one_bit_prefix_rule,
            &[("IPv6.src", (1 << 127) - 1)]
        ));

        let one_hundred_twenty_seven_prefix_rule =
            Rule::new(4, ONE_HUNDRED_TWENTY_SEVEN_PREFIX_FIELDS);
        assert!(rule_matches(
            &one_hundred_twenty_seven_prefix_rule,
            &[("IPv6.src", u128::MAX - 1)]
        ));
        assert!(!rule_matches(
            &one_hundred_twenty_seven_prefix_rule,
            &[("IPv6.src", u128::MAX - 2)]
        ));

        let full_prefix_rule = Rule::new(5, FULL_PREFIX_FIELDS);
        assert!(rule_matches(&full_prefix_rule, &[("IPv6.src", u128::MAX)]));
        assert!(!rule_matches(
            &full_prefix_rule,
            &[("IPv6.src", u128::MAX - 1)]
        ));
    }

    #[test]
    fn msb_matching_rejects_invalid_widths_and_arguments() {
        const ARGUMENT_TOO_LARGE_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "IPv6.src",
            128,
            Mo::Msb,
            Cda::Lsb,
            0,
            Some(129),
            None,
        )];
        const ZERO_WIDTH_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "invalid.zero_width",
            0,
            Mo::Msb,
            Cda::Lsb,
            0,
            Some(0),
            None,
        )];
        const WIDTH_TOO_LARGE_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "invalid.too_wide",
            129,
            Mo::Msb,
            Cda::Lsb,
            0,
            Some(1),
            None,
        )];

        assert!(!rule_matches(
            &Rule::new(6, ARGUMENT_TOO_LARGE_FIELDS),
            &[("IPv6.src", 0)]
        ));
        assert!(!rule_matches(
            &Rule::new(7, ZERO_WIDTH_FIELDS),
            &[("invalid.zero_width", 0)]
        ));
        assert!(!rule_matches(
            &Rule::new(8, WIDTH_TOO_LARGE_FIELDS),
            &[("invalid.too_wide", 0)]
        ));
    }

    #[test]
    fn descriptor_width_validation_precedes_every_mo_and_cda() {
        for &mo in KNOWN_MATCHING_OPERATORS {
            for &cda in KNOWN_COMPRESSION_ACTIONS {
                let mapping = matches!(mo, Mo::MatchMapping).then_some(WIDTH_ONE_MAPPING);
                for invalid_width in [0, 129] {
                    let rule = one_field_rule(descriptor_for(invalid_width, mo, cda, 0, mapping));
                    assert!(!rule_matches(&rule, &[("test.width", 0)]));
                    assert!(!rule_matches(&rule, &[]));
                }
            }
        }
    }

    #[test]
    fn present_value_must_fit_for_every_mo_and_cda() {
        for &mo in KNOWN_MATCHING_OPERATORS {
            for &cda in KNOWN_COMPRESSION_ACTIONS {
                let mapping = matches!(mo, Mo::MatchMapping).then_some(WIDTH_ONE_MAPPING);
                let rule = one_field_rule(descriptor_for(1, mo, cda, 1, mapping));
                assert!(!rule_matches(&rule, &[("test.width", 2)]));
            }
        }
    }

    #[test]
    fn representable_boundaries_match_for_each_mo_and_cda() {
        for (length_bits, max_value, mapping) in [
            (1, 1, WIDTH_ONE_MAPPING),
            (128, u128::MAX, WIDTH_128_MAPPING),
        ] {
            for &(mo, cda) in VALID_MO_CDA_PAIRS {
                let mapping = matches!(mo, Mo::MatchMapping).then_some(mapping);
                let rule = one_field_rule(descriptor_for(length_bits, mo, cda, max_value, mapping));
                assert!(rule_matches(&rule, &[("test.width", max_value)]));
            }
        }
    }

    #[test]
    fn target_and_all_mapping_entries_must_fit() {
        let equal = one_field_rule(descriptor_for(1, Mo::Equal, Cda::NotSent, 2, None));
        assert!(!rule_matches(&equal, &[("test.width", 1)]));

        let zero_prefix = one_field_rule(descriptor_for(1, Mo::Msb, Cda::Lsb, 2, None));
        assert!(!rule_matches(&zero_prefix, &[("test.width", 1)]));

        let reconstructed = one_field_rule(descriptor_for(1, Mo::Ignore, Cda::NotSent, 2, None));
        assert!(!rule_matches(&reconstructed, &[("test.width", 1)]));

        let canonical_target =
            one_field_rule(descriptor_for(1, Mo::Ignore, Cda::ValueSent, 2, None));
        assert!(!rule_matches(&canonical_target, &[("test.width", 1)]));

        let mapping = one_field_rule(descriptor_for(
            1,
            Mo::MatchMapping,
            Cda::MappingSent,
            0,
            Some(INVALID_WIDTH_ONE_MAPPING),
        ));
        assert!(!rule_matches(&mapping, &[("test.width", 0)]));

        let unused_mapping = one_field_rule(descriptor_for(
            1,
            Mo::Ignore,
            Cda::ValueSent,
            0,
            Some(INVALID_WIDTH_ONE_MAPPING),
        ));
        assert!(!rule_matches(&unused_mapping, &[("test.width", 0)]));
    }

    #[test]
    fn msb_zero_prefix_requires_representable_packet_value() {
        let rule = one_field_rule(descriptor_for(1, Mo::Msb, Cda::Lsb, 1, None));
        assert!(rule_matches(&rule, &[("test.width", 0)]));
        assert!(rule_matches(&rule, &[("test.width", 1)]));
        assert!(!rule_matches(&rule, &[("test.width", 2)]));
    }

    #[test]
    fn lsb_cda_requires_msb_with_the_same_bounded_argument() {
        for mo_arg in [None, Some(2)] {
            let fd = FieldDescriptor::new("test.width", 1, Mo::Msb, Cda::Lsb, 1, mo_arg, None);
            assert!(!rule_matches(&one_field_rule(fd), &[("test.width", 1)]));
        }

        for mo_arg in [0, 1] {
            let fd =
                FieldDescriptor::new("test.width", 1, Mo::Msb, Cda::Lsb, 1, Some(mo_arg), None);
            assert!(rule_matches(&one_field_rule(fd), &[("test.width", 1)]));
        }

        for &mo in KNOWN_MATCHING_OPERATORS {
            if mo == Mo::Msb {
                continue;
            }
            let mapping = matches!(mo, Mo::MatchMapping).then_some(WIDTH_ONE_MAPPING);
            let fd = FieldDescriptor::new("test.width", 1, mo, Cda::Lsb, 1, Some(1), mapping);
            assert!(!rule_matches(&one_field_rule(fd), &[("test.width", 1)]));
        }

        let width_128 = FieldDescriptor::new(
            "test.width",
            128,
            Mo::Msb,
            Cda::Lsb,
            u128::MAX,
            Some(128),
            None,
        );
        assert!(rule_matches(
            &one_field_rule(width_128),
            &[("test.width", u128::MAX)]
        ));
    }

    #[test]
    fn mapping_sent_requires_match_mapping_with_two_unique_width_valid_entries() {
        for mapping in [
            None,
            Some(EMPTY_MAPPING),
            Some(SINGLETON_MAPPING),
            Some(DUPLICATE_MAPPING),
            Some(INVALID_WIDTH_ONE_MAPPING),
        ] {
            let fd = FieldDescriptor::new(
                "test.width",
                1,
                Mo::MatchMapping,
                Cda::MappingSent,
                1,
                None,
                mapping,
            );
            assert!(!rule_matches(&one_field_rule(fd), &[("test.width", 1)]));
        }

        let valid = descriptor_for(
            1,
            Mo::MatchMapping,
            Cda::MappingSent,
            1,
            Some(MULTI_MAPPING),
        );
        assert!(rule_matches(&one_field_rule(valid), &[("test.width", 1)]));

        let duplicate_width_128 = descriptor_for(
            128,
            Mo::MatchMapping,
            Cda::MappingSent,
            u128::MAX,
            Some(DUPLICATE_WIDTH_128_MAPPING),
        );
        let duplicate_rule = one_field_rule(duplicate_width_128);
        assert!(!rule_matches(&duplicate_rule, &[("test.width", u128::MAX)]));
        let duplicate_context = SchcContext::new(Box::leak(Box::new([duplicate_rule])));
        assert!(duplicate_context.get(100).is_none());

        for &mo in KNOWN_MATCHING_OPERATORS {
            if mo == Mo::MatchMapping {
                continue;
            }
            let fd = FieldDescriptor::new(
                "test.width",
                1,
                mo,
                Cda::MappingSent,
                1,
                matches!(mo, Mo::Msb).then_some(0),
                Some(MULTI_MAPPING),
            );
            assert!(!rule_matches(&one_field_rule(fd), &[("test.width", 1)]));
        }
    }

    #[test]
    fn only_the_explicit_lossless_mo_cda_matrix_is_selectable() {
        for &mo in KNOWN_MATCHING_OPERATORS {
            for &cda in KNOWN_COMPRESSION_ACTIONS {
                let mapping = matches!(mo, Mo::MatchMapping).then_some(WIDTH_ONE_MAPPING);
                let rule = one_field_rule(descriptor_for(1, mo, cda, 1, mapping));
                let expected = VALID_MO_CDA_PAIRS.contains(&(mo, cda));
                assert_eq!(rule_matches(&rule, &[("test.width", 1)]), expected);
            }
        }
    }

    #[test]
    fn descriptor_metadata_is_present_if_and_only_if_its_mo_requires_it() {
        let missing_msb_arg =
            FieldDescriptor::new("test.width", 1, Mo::Msb, Cda::Lsb, 0, None, None);
        assert!(!rule_matches(
            &one_field_rule(missing_msb_arg),
            &[("test.width", 0)]
        ));

        let extraneous_arg =
            FieldDescriptor::new("test.width", 1, Mo::Equal, Cda::NotSent, 0, Some(0), None);
        assert!(!rule_matches(
            &one_field_rule(extraneous_arg),
            &[("test.width", 0)]
        ));

        let missing_mapping = descriptor_for(1, Mo::MatchMapping, Cda::MappingSent, 0, None);
        assert!(!rule_matches(
            &one_field_rule(missing_mapping),
            &[("test.width", 0)]
        ));

        let extraneous_mapping =
            descriptor_for(1, Mo::Ignore, Cda::ValueSent, 0, Some(MULTI_MAPPING));
        assert!(!rule_matches(
            &one_field_rule(extraneous_mapping),
            &[("test.width", 0)]
        ));
    }

    #[test]
    fn selectable_lossless_rules_round_trip_through_the_generic_codec() {
        const ROUND_TRIP_MAPPING: &[u128] = &[10, 20, 30];

        assert_generic_round_trip(descriptor_for(8, Mo::Equal, Cda::NotSent, 42, None), 42, 42);
        assert_generic_round_trip(
            FieldDescriptor::new(
                "test.width",
                8,
                Mo::Msb,
                Cda::Lsb,
                0b1010_0000,
                Some(4),
                None,
            ),
            0b1010_0101,
            0b1010_0101,
        );
        assert_generic_round_trip(
            descriptor_for(
                8,
                Mo::MatchMapping,
                Cda::MappingSent,
                0,
                Some(ROUND_TRIP_MAPPING),
            ),
            20,
            20,
        );
        assert_generic_round_trip(
            descriptor_for(8, Mo::Ignore, Cda::ValueSent, 0, None),
            255,
            255,
        );
    }

    #[test]
    fn every_supported_pair_is_encodable_at_one_and_128_bits() {
        for (length_bits, value, mapping) in [
            (1, 1, WIDTH_ONE_MAPPING),
            (128, u128::MAX, WIDTH_128_MAPPING),
        ] {
            for &(mo, cda) in VALID_MO_CDA_PAIRS {
                let mapping = matches!(mo, Mo::MatchMapping).then_some(mapping);
                let expected = if matches!(cda, Cda::Compute) {
                    0
                } else {
                    value
                };
                assert_generic_round_trip(
                    descriptor_for(length_bits, mo, cda, value, mapping),
                    value,
                    expected,
                );
            }
        }
    }

    #[test]
    fn invalid_rule_falls_through_to_a_safe_selectable_rule() {
        let absent_from_mapping = descriptor_for(
            2,
            Mo::MatchMapping,
            Cda::MappingSent,
            1,
            Some(MULTI_MAPPING),
        );
        let safe_value_sent = descriptor_for(2, Mo::Ignore, Cda::ValueSent, 0, None);
        let rules = Box::leak(Box::new([
            Rule::new(1, Box::leak(Box::new([absent_from_mapping]))),
            Rule::new(2, Box::leak(Box::new([safe_value_sent]))),
            UNCOMPRESSED_RULE,
        ]));
        let context = SchcContext::new(rules);

        let selected = context.select_rule(&[("test.width", 2)]).unwrap();
        assert_eq!(selected.rule_id, 2);
        assert!(context.get(UNCOMPRESSED_RULE.rule_id).is_some());

        let mut residue = [0u8; 8];
        let residue_len = generic_compress(selected, &[2], &mut residue).unwrap();
        let mut reconstructed = [0u128; 1];
        generic_decompress(selected, &residue[..residue_len], &mut reconstructed).unwrap();
        assert_eq!(reconstructed, [2]);
    }

    #[test]
    fn rule_matches_mapping() {
        const MAPPING_VALUES: &[u128] = &[10, 20, 30];
        const MAPPING_FIELDS: &[FieldDescriptor] = &[FieldDescriptor::new(
            "test.field",
            8,
            Mo::MatchMapping,
            Cda::MappingSent,
            0,
            None,
            Some(MAPPING_VALUES),
        )];
        const MAPPING_RULE: Rule = Rule::new(42, MAPPING_FIELDS);

        let fields_match: &[(FieldId, u128)] = &[("test.field", 20)];
        assert!(rule_matches(&MAPPING_RULE, fields_match));

        let fields_no_match: &[(FieldId, u128)] = &[("test.field", 99)];
        assert!(!rule_matches(&MAPPING_RULE, fields_no_match));
    }
}
