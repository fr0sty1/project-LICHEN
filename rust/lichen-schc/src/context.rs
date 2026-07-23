//! SCHC rule context and selection (RFC 8724 section 7).
//!
//! A [`SchcContext`] holds the active rule set and selects a matching rule for
//! a set of field values: the first rule (by ascending rule ID) whose every
//! descriptor is satisfied -- EQUAL/MSB constraints hold and all fields needed
//! for the residue are present. If no compression rule matches, selection falls
//! back to the uncompressed rule (ID 255).
//!
//! This mirrors the Python `lichen.schc.context` module.

use crate::rules::{Cda, FieldDescriptor, Mo, Rule, UNCOMPRESSED_RULE};

/// Error returned when no rule matches.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoMatchingRuleError;

impl core::fmt::Display for NoMatchingRuleError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "no SCHC rule matches the given fields")
    }
}

impl core::error::Error for NoMatchingRuleError {}

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

/// Whether `fields` satisfy every descriptor of `rule`.
///
/// Returns true if all descriptors match:
/// - For `Mo::Equal`: field value must equal target_value
/// - For `Mo::Msb`: the most-significant `mo_arg` bits must match
/// - For `Mo::MatchMapping`: value must be in the mapping table from rule
/// - For `Mo::Ignore`: always matches (field may or may not be present)
pub fn rule_matches(rule: &Rule, fields: &[(FieldId, u128)]) -> bool {
    for fd in rule.fields {
        let value = find_field(fields, fd.field_id);

        match value {
            None => {
                // Field not present -- allowed only if not required
                if field_requires_value(fd) {
                    return false;
                }
            }
            Some(val) => {
                match fd.mo {
                    Mo::Equal => {
                        if val != fd.target_value {
                            return false;
                        }
                    }
                    Mo::Msb => {
                        if let Some(mo_arg) = fd.mo_arg {
                            if mo_arg > fd.length_bits {
                                return false; // invalid mo_arg, rule cannot match
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
    pub fn get(&self, rule_id: u8) -> Option<&Rule> {
        self.rules.iter().find(|rule| rule.rule_id == rule_id)
    }

    /// Find the first matching compression rule, or None if none matches.
    ///
    /// Skips the uncompressed rule (ID 255) during selection.
    pub fn select_rule(&self, fields: &[(FieldId, u128)]) -> Option<&Rule> {
        for rule in self.rules {
            if rule.rule_id == UNCOMPRESSED_RULE.rule_id {
                continue;
            }
            if rule_matches(rule, fields) {
                return Some(rule);
            }
        }
        None
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
    use super::*;
    use crate::rules::{Cda, FieldDescriptor, Mo, Rule};

    // Test descriptors for a simple rule
    const TEST_FIELDS: &[FieldDescriptor] = &[
        FieldDescriptor {
            field_id: "IPv6.version",
            length_bits: 4,
            mo: Mo::Equal,
            cda: Cda::NotSent,
            target_value: 6,
            mo_arg: None,
            mapping: None,
        },
        FieldDescriptor {
            field_id: "IPv6.hop_limit",
            length_bits: 8,
            mo: Mo::Ignore,
            cda: Cda::ValueSent,
            target_value: 64,
            mo_arg: None,
            mapping: None,
        },
    ];

    const TEST_RULE: Rule = Rule {
        rule_id: 0,
        fields: TEST_FIELDS,
    };

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
    fn msb_matching() {
        // Test MSB matching operator
        const MSB_FIELDS: &[FieldDescriptor] = &[FieldDescriptor {
            field_id: "IPv6.src",
            length_bits: 128,
            mo: Mo::Msb,
            cda: Cda::Lsb,
            target_value: 0xFE80_0000_0000_0000_0000_0000_0000_0000,
            mo_arg: Some(64), // Match first 64 bits
            mapping: None,
        }];
        const MSB_RULE: Rule = Rule {
            rule_id: 1,
            fields: MSB_FIELDS,
        };

        // Link-local address should match
        let fields: &[(FieldId, u128)] = &[("IPv6.src", 0xFE80_0000_0000_0000_1234_5678_9ABC_DEF0)];
        assert!(rule_matches(&MSB_RULE, fields));

        // Global address should not match
        let fields: &[(FieldId, u128)] = &[("IPv6.src", 0x2001_0DB8_0000_0000_1234_5678_9ABC_DEF0)];
        assert!(!rule_matches(&MSB_RULE, fields));
    }

    #[test]
    fn rule_matches_mapping() {
        const MAPPING_FIELDS: &[FieldDescriptor] = &[FieldDescriptor {
            field_id: "test.field",
            length_bits: 8,
            mo: Mo::MatchMapping,
            cda: Cda::MappingSent,
            target_value: 0,
            mo_arg: None,
            mapping: Some(&[10u128, 20, 30]),
        }];
        const MAPPING_RULE: Rule = Rule {
            rule_id: 42,
            fields: MAPPING_FIELDS,
        };

        let fields_match: &[(FieldId, u128)] = &[("test.field", 20)];
        assert!(rule_matches(&MAPPING_RULE, fields_match));

        let fields_no_match: &[(FieldId, u128)] = &[("test.field", 99)];
        assert!(!rule_matches(&MAPPING_RULE, fields_no_match));
    }
}
