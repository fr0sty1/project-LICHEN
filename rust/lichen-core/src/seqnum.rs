// SPDX-License-Identifier: GPL-3.0-or-later
// SPDX-FileCopyrightText: The contributors to the LICHEN project

//! RFC 1982 serial-number arithmetic for route freshness.
//!
//! Routing protocols such as LOADng compare sequence numbers that wrap around
//! their modulus. Naive integer comparison breaks at the wrap point (e.g.
//! `0xFFFF` is followed by `0x0000`). RFC 1982 defines a partial order over
//! serial numbers: `a < b` exactly when `(b - a) mod 2^N` lies in
//! `(0, 2^(N-1))`.
//!
//! This mirrors the Python reference `lichen.gradient.SeqNum` (16-bit space).
//! Note one divergence: the Python class derives its ordering via
//! `functools.total_ordering`, which resolves the undefined half-window case
//! (`diff == 2^(N-1)`) as `Greater`. Per RFC 1982 section 3.2 that case is
//! undefined; here it is `None` and both `a < b` and `a > b` are `false`.

use core::cmp::Ordering;

/// Bit width of the sequence-number space.
pub const SEQ_BITS: u8 = 16;

/// Size of the sequence-number space: `2^SEQ_BITS`.
pub const SEQ_MODULUS: u32 = 1 << SEQ_BITS;

/// Half the space: the edge of the RFC 1982 comparison window.
pub const SEQ_HALF: u16 = 1 << (SEQ_BITS - 1);

/// 16-bit sequence number with RFC 1982 serial-number arithmetic.
///
/// The value is always in `0..=0xFFFF` (enforced by the `u16` backing type,
/// mirroring the Python reference's `value & 0xFFFF` normalization).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SeqNum(u16);

impl SeqNum {
    /// Lowest representable sequence number.
    pub const MIN: SeqNum = SeqNum(0);

    /// Highest representable sequence number.
    pub const MAX: SeqNum = SeqNum(u16::MAX);

    /// Construct from the raw `u16` wire value.
    ///
    /// The `u16` backing type already enforces the `0..=0xFFFF` bounds, so
    /// this is total (the analog of the Python reference's constructor with
    /// an in-range value).
    pub const fn new(value: u16) -> Self {
        SeqNum(value)
    }

    /// The inner `u16` value.
    pub const fn value(self) -> u16 {
        self.0
    }

    /// Wrap-aware successor: one step forward with wraparound at the modulus.
    pub const fn increment(self) -> Self {
        SeqNum(self.0.wrapping_add(1))
    }

    /// Advance by `n` steps with wraparound at the modulus.
    pub const fn wrapping_add(self, n: u16) -> Self {
        SeqNum(self.0.wrapping_add(n))
    }

    /// RFC 1982 serial-number comparison.
    ///
    /// Returns:
    /// - `Some(Less)` when `(other - self) mod 2^16` is in `(0, 2^15)`
    /// - `Some(Greater)` when it is in `(2^15, 2^16)`
    /// - `Some(Equal)` when the values are identical
    /// - `None` when the difference is exactly `2^15`: RFC 1982 section 3.2
    ///   leaves this case undefined, so the pair is unordered
    pub const fn rfc1982_cmp(self, other: Self) -> Option<Ordering> {
        let diff = other.0.wrapping_sub(self.0);
        if diff == 0 {
            Some(Ordering::Equal)
        } else if diff < SEQ_HALF {
            Some(Ordering::Less)
        } else if diff > SEQ_HALF {
            Some(Ordering::Greater)
        } else {
            None
        }
    }
}

impl PartialOrd for SeqNum {
    /// Partial order per RFC 1982. The undefined half-window case compares as
    /// `None`, so `<`, `>`, `<=`, and `>=` are all `false` there (while the
    /// values remain unequal under [`PartialEq`]).
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        self.rfc1982_cmp(*other)
    }
}

impl From<u16> for SeqNum {
    fn from(value: u16) -> Self {
        SeqNum(value)
    }
}

impl From<SeqNum> for u16 {
    fn from(value: SeqNum) -> Self {
        value.0
    }
}

impl From<SeqNum> for usize {
    fn from(value: SeqNum) -> Self {
        usize::from(value.0)
    }
}

impl TryFrom<usize> for SeqNum {
    type Error = core::num::TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        u16::try_from(value).map(SeqNum)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use core::cmp::Ordering;

    /// Independent RFC 1982 oracle recomputed from the RFC text with signed
    /// arithmetic (no wrapping operations shared with the implementation).
    ///
    /// RFC 1982 section 3.2: with N-bit serial numbers, i1 < i2 iff
    /// 0 < (i2 - i1) mod 2^N < 2^(N-1); i1 > i2 iff
    /// 2^(N-1) < (i2 - i1) mod 2^N < 2^N; equal iff identical; the exact
    /// half-space difference 2^(N-1) is undefined.
    fn oracle_cmp(a: u16, b: u16) -> Option<Ordering> {
        let diff = (i64::from(b) - i64::from(a)).rem_euclid(65_536);
        if diff == 0 {
            Some(Ordering::Equal)
        } else if diff < 32_768 {
            Some(Ordering::Less)
        } else if diff > 32_768 {
            Some(Ordering::Greater)
        } else {
            None
        }
    }

    /// Golden vectors produced by the independent Python reference
    /// `lichen.gradient.SeqNum` (lt/gt/eq as printed by that implementation).
    /// Pairs whose difference is exactly 0x8000 are the undefined window:
    /// the Python class's `total_ordering` artifact reports gt=true there,
    /// while its RFC-derived `__lt__` is false in both directions; the Rust
    /// type models the RFC (unordered).
    #[test]
    fn golden_vectors_from_python_reference() {
        let cases: &[(u16, u16, Option<Ordering>)] = &[
            (0xFFFF, 0x0000, Some(Ordering::Less)), // wrap: 0xFFFF precedes 0
            (0xFFFE, 0x0002, Some(Ordering::Less)), // diff 4 across wrap
            (0x7FFF, 0xFFFF, None),                 // half-window (Python lt=false)
            (0xFFFF, 0x7FFF, None),                 // half-window (Python lt=false)
            (0x7FFF, 0x8000, Some(Ordering::Less)), // diff 1
            (0x7FFF, 0x0000, Some(Ordering::Greater)), // diff 0x8001
            (0x0000, 0x0001, Some(Ordering::Less)), // diff 1
            (0x0000, 0x7FFF, Some(Ordering::Less)), // diff 0x7FFF, last ordered "older"
            (0x0000, 0x8000, None),                 // half-window (Python lt=false)
            (0x0000, 0x8001, Some(Ordering::Greater)), // diff 0x8001
            (0x0005, 0x0005, Some(Ordering::Equal)), // identical values
            (0x8000, 0x0000, None),                 // half-window (Python lt=false)
            (0x8001, 0x0000, Some(Ordering::Less)), // diff 0x7FFF backwards
            (0xFFFF, 0xFFFE, Some(Ordering::Greater)), // diff 0xFFFF
        ];
        for &(a, b, expected) in cases {
            assert_eq!(
                SeqNum::new(a).rfc1982_cmp(SeqNum::new(b)),
                expected,
                "rfc1982_cmp({a:#06x}, {b:#06x})"
            );
            assert_eq!(oracle_cmp(a, b), expected, "oracle({a:#06x}, {b:#06x})");
        }
    }

    #[test]
    fn partial_ordering_operators_match_vectors() {
        let cases: &[(u16, u16, Option<Ordering>)] = &[
            (0xFFFF, 0x0000, Some(Ordering::Less)),
            (0xFFFE, 0x0002, Some(Ordering::Less)),
            (0x7FFF, 0x8000, Some(Ordering::Less)),
            (0x0000, 0x0001, Some(Ordering::Less)),
            (0x0000, 0x7FFF, Some(Ordering::Less)),
            (0x8001, 0x0000, Some(Ordering::Less)),
            (0x7FFF, 0x0000, Some(Ordering::Greater)),
            (0x0000, 0x8001, Some(Ordering::Greater)),
            (0xFFFF, 0xFFFE, Some(Ordering::Greater)),
            (0x0005, 0x0005, Some(Ordering::Equal)),
        ];
        for &(a, b, expected) in cases {
            let (x, y) = (SeqNum::new(a), SeqNum::new(b));
            match expected {
                Some(Ordering::Less) => {
                    assert!(x < y && x <= y, "{a:#06x} < {b:#06x}");
                    assert!(!(x > y) && !(x >= y), "{a:#06x} > {b:#06x}");
                    assert!(x != y);
                }
                Some(Ordering::Greater) => {
                    assert!(x > y && x >= y, "{a:#06x} > {b:#06x}");
                    assert!(!(x < y) && !(x <= y), "{a:#06x} < {b:#06x}");
                    assert!(x != y);
                }
                Some(Ordering::Equal) => {
                    assert!(x == y);
                    assert!(!(x < y) && !(x > y));
                }
                None => {
                    assert!(!(x < y) && !(x > y) && !(x <= y) && !(x >= y));
                }
            }
        }
    }

    #[test]
    fn undefined_half_window_is_unordered() {
        // RFC 1982 section 3.2: when (b - a) mod 2^16 == 2^15, neither less,
        // nor greater, nor (beyond plain equality) comparable.
        for &(a, b) in &[
            (0x7FFF, 0xFFFF),
            (0xFFFF, 0x7FFF),
            (0x0000, 0x8000),
            (0x8000, 0x0000),
            (0x1234, 0x9234),
        ] {
            let (x, y) = (SeqNum::new(a), SeqNum::new(b));
            assert_eq!(x.rfc1982_cmp(y), None, "{a:#06x} vs {b:#06x}");
            assert_eq!(y.rfc1982_cmp(x), None, "{b:#06x} vs {a:#06x}");
            assert!(!(x < y) && !(x > y) && !(x <= y) && !(x >= y));
            assert!(x != y, "unordered does not mean equal");
        }
    }

    #[test]
    fn equal_values_compare_equal() {
        for a in [0u16, 1, 0x7FFF, 0x8000, 0xFFFF] {
            let x = SeqNum::new(a);
            assert_eq!(x.rfc1982_cmp(x), Some(Ordering::Equal));
            assert_eq!(oracle_cmp(a, a), Some(Ordering::Equal));
            assert!(x == x);
            assert!(!(x < x) && !(x > x));
        }
    }

    #[test]
    fn exhaustive_window_sweep_against_oracle() {
        // Every pairing of boundary anchors against the full space must agree
        // with the independently computed RFC 1982 oracle.
        let anchors = [
            0x0000, 0x0001, 0x7FFE, 0x7FFF, 0x8000, 0x8001, 0xFFFE, 0xFFFF, 0x1234, 0xABCD,
        ];
        for &a in &anchors {
            for b in 0..=u16::MAX {
                assert_eq!(
                    SeqNum::new(a).rfc1982_cmp(SeqNum::new(b)),
                    oracle_cmp(a, b),
                    "rfc1982_cmp({a:#06x}, {b:#06x})"
                );
            }
        }
    }

    #[test]
    fn deterministic_stride_sweep_against_oracle() {
        // LCG-driven deterministic sweep over arbitrary pairs (not just
        // boundary anchors) must also agree with the oracle.
        let mut state = 0x1234_5678u32;
        for _ in 0..100_000 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            let a = state as u16;
            let b = (state >> 16) as u16;
            assert_eq!(
                SeqNum::new(a).rfc1982_cmp(SeqNum::new(b)),
                oracle_cmp(a, b),
                "rfc1982_cmp({a:#06x}, {b:#06x})"
            );
        }
    }

    #[test]
    fn increment_wraps_at_modulus() {
        // Bead-required wrap behavior: 0xFFFF -> 0x0000.
        let mut s = SeqNum::new(0xFFFD);
        s = s.increment();
        assert_eq!(s, SeqNum::new(0xFFFE));
        s = s.increment();
        assert_eq!(s, SeqNum::new(0xFFFF));
        s = s.increment();
        assert_eq!(s, SeqNum::new(0x0000));
        s = s.increment();
        assert_eq!(s, SeqNum::new(0x0001));
    }

    #[test]
    fn wrapping_add_boundaries() {
        assert_eq!(SeqNum::MAX.wrapping_add(1), SeqNum::MIN);
        assert_eq!(SeqNum::MIN.wrapping_add(0xFFFF), SeqNum::MAX);
        assert_eq!(SeqNum::MIN.wrapping_add(0x8000), SeqNum::new(0x8000));
        assert_eq!(SeqNum::new(0x1234).wrapping_add(0), SeqNum::new(0x1234));
        // Advance by modulus-1 lands one behind.
        assert_eq!(
            SeqNum::new(0xC0DE).wrapping_add(0xFFFF),
            SeqNum::new(0xC0DD)
        );
    }

    #[test]
    fn increment_matches_wrapping_add_one() {
        let mut s = 0x9ABCu16;
        for _ in 0..70_000 {
            let x = SeqNum::new(s);
            assert_eq!(x.increment(), x.wrapping_add(1));
            s = s.wrapping_add(1);
        }
    }

    #[test]
    fn value_stays_in_bounds() {
        assert_eq!(SeqNum::MIN.value(), 0);
        assert_eq!(SeqNum::MAX.value(), 0xFFFF);
        assert_eq!(SEQ_MODULUS, 65_536);
        assert_eq!(usize::from(SEQ_HALF), 32_768);
    }

    #[test]
    fn conversions_round_trip() {
        let s = SeqNum::from(0xBEEFu16);
        assert_eq!(u16::from(s), 0xBEEF);
        assert_eq!(usize::from(s), 0xBEEF_usize);
        assert_eq!(SeqNum::try_from(0xBEEF_usize), Ok(SeqNum::new(0xBEEF)));
        assert!(SeqNum::try_from(0x1_0000_usize).is_err());
        assert_eq!(SeqNum::default(), SeqNum::MIN);
        assert_eq!(s.value(), 0xBEEF);
    }
}
