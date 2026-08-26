//! Time-source failover (spec 09 section 14.6).
//!
//! When the preferred class is missing, pick the next policy-ranked class
//! that can establish wall-clock time. Monotonic never wins.

use crate::precedence::SourcePrecedencePolicy;
use crate::time_source::TimeSourceClass;

/// Best available wall-clock source under `policy`, or `None`.
pub fn select_wall_clock_source(
    policy: SourcePrecedencePolicy,
    available: &[TimeSourceClass],
) -> Option<TimeSourceClass> {
    let mut best: Option<TimeSourceClass> = None;
    let mut i = 0;
    while i < available.len() {
        let class = available[i];
        if class.can_establish_wall_clock() {
            best = Some(match best {
                None => class,
                Some(cur) => policy.preferred(cur, class),
            });
        }
        i += 1;
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn falls_back_when_gnss_missing() {
        let policy = SourcePrecedencePolicy::default();
        assert_eq!(
            select_wall_clock_source(
                policy,
                &[TimeSourceClass::Network, TimeSourceClass::Monotonic]
            ),
            Some(TimeSourceClass::Network)
        );
        assert_eq!(
            select_wall_clock_source(policy, &[TimeSourceClass::Monotonic]),
            None
        );
        assert_eq!(
            select_wall_clock_source(policy, &[TimeSourceClass::Manual, TimeSourceClass::Gnss]),
            Some(TimeSourceClass::Gnss)
        );
    }
}
