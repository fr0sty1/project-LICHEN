//! Time source precedence policy (spec 09 section 14.6).
//!
//! Matches Python `SourcePrecedencePolicy`: every [`TimeSourceClass`] appears
//! exactly once; lower rank is higher quality.

use crate::time_source::TimeSourceClass;

/// Configurable ranking of time sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SourcePrecedencePolicy {
    order: [TimeSourceClass; 6],
}

/// Invalid precedence list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrecedenceError {
    /// List is missing a class, has a duplicate, or is the wrong length.
    NotAPermutation,
}

impl Default for SourcePrecedencePolicy {
    fn default() -> Self {
        Self {
            order: TimeSourceClass::ALL,
        }
    }
}

impl SourcePrecedencePolicy {
    /// Build a policy from an explicit ranking (best first).
    pub const fn new(order: [TimeSourceClass; 6]) -> Result<Self, PrecedenceError> {
        let mut seen = [false; 6];
        let mut i = 0;
        while i < 6 {
            let idx = class_index(order[i]);
            if seen[idx] {
                return Err(PrecedenceError::NotAPermutation);
            }
            seen[idx] = true;
            i += 1;
        }
        Ok(Self { order })
    }

    /// Rank of `class` (0 = highest precedence).
    pub const fn rank(self, class: TimeSourceClass) -> usize {
        let mut i = 0;
        while i < 6 {
            if class_eq(self.order[i], class) {
                return i;
            }
            i += 1;
        }
        6
    }

    /// The higher-quality (lower rank) of two classes.
    pub const fn preferred(self, left: TimeSourceClass, right: TimeSourceClass) -> TimeSourceClass {
        if self.rank(left) <= self.rank(right) {
            left
        } else {
            right
        }
    }

    /// Ranking from best to worst.
    pub const fn order(self) -> [TimeSourceClass; 6] {
        self.order
    }
}

const fn class_index(class: TimeSourceClass) -> usize {
    match class {
        TimeSourceClass::Gnss => 0,
        TimeSourceClass::Network => 1,
        TimeSourceClass::LocalClient => 2,
        TimeSourceClass::Manual => 3,
        TimeSourceClass::InternalRtc => 4,
        TimeSourceClass::Monotonic => 5,
    }
}

const fn class_eq(a: TimeSourceClass, b: TimeSourceClass) -> bool {
    class_index(a) == class_index(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_prefers_gnss_over_monotonic() {
        let policy = SourcePrecedencePolicy::default();
        assert_eq!(policy.rank(TimeSourceClass::Gnss), 0);
        assert_eq!(policy.rank(TimeSourceClass::Monotonic), 5);
        assert_eq!(
            policy.preferred(TimeSourceClass::Network, TimeSourceClass::Manual),
            TimeSourceClass::Network
        );
    }

    #[test]
    fn custom_order_is_configurable() {
        let mut order = TimeSourceClass::ALL;
        order.swap(0, 5);
        let policy = SourcePrecedencePolicy::new(order).expect("perm");
        assert_eq!(
            policy.preferred(TimeSourceClass::Gnss, TimeSourceClass::Monotonic),
            TimeSourceClass::Monotonic
        );
    }

    #[test]
    fn duplicate_is_rejected() {
        let mut order = TimeSourceClass::ALL;
        order[1] = TimeSourceClass::Gnss;
        assert_eq!(
            SourcePrecedencePolicy::new(order),
            Err(PrecedenceError::NotAPermutation)
        );
    }
}
