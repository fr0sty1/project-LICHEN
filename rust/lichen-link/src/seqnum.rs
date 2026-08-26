//! Link-layer sequence number newtype.
//!
//! Wraps a u16 sequence number with domain-specific semantics:
//! - Per-epoch, wrapping arithmetic
//! - Used for replay protection at the link layer
//!
//! The newtype provides type safety to prevent mixing link-layer
//! sequence numbers with other u16 values (e.g., message IDs, ports).

/// Link-layer sequence number (u16, wrapping per epoch).
///
/// This is the sequence number included in each LICHEN frame for replay
/// protection. It wraps around at 65535 and is reset when the epoch changes.
///
/// # Wire Format
///
/// Encoded as big-endian u16 in the frame header (spec 4.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[repr(transparent)]
pub struct LinkSeqNum(u16);

impl LinkSeqNum {
    /// Create a new link sequence number.
    #[inline]
    pub const fn new(value: u16) -> Self {
        Self(value)
    }

    /// Get the raw u16 value.
    #[inline]
    pub const fn get(self) -> u16 {
        self.0
    }

    /// Convert to big-endian bytes for wire format.
    #[inline]
    pub const fn to_be_bytes(self) -> [u8; 2] {
        self.0.to_be_bytes()
    }

    /// Parse from big-endian bytes.
    #[inline]
    pub const fn from_be_bytes(bytes: [u8; 2]) -> Self {
        Self(u16::from_be_bytes(bytes))
    }

    /// Increment by one with wrapping.
    #[inline]
    #[must_use = "returns a new value; does not modify self"]
    pub const fn wrapping_next(self) -> Self {
        Self(self.0.wrapping_add(1))
    }

    /// Increment in place, returning the old value.
    ///
    /// Useful for TX paths where you want to use the current sequence
    /// number and advance to the next.
    #[inline]
    pub fn fetch_increment(&mut self) -> Self {
        let old = *self;
        self.0 = self.0.wrapping_add(1);
        old
    }

    /// 24-bit logical replay counter: `(epoch << 16) | seqnum` (spec 4.4).
    #[inline]
    pub const fn with_epoch(self, epoch: u8) -> u32 {
        logical_counter(epoch, self.0)
    }

    /// Compute signed distance from `other` to `self`.
    ///
    /// Positive means `self` is newer than `other`.
    /// Used for replay window comparisons.
    ///
    /// # Example
    ///
    /// ```
    /// # use lichen_link::seqnum::LinkSeqNum;
    /// let a = LinkSeqNum::new(100);
    /// let b = LinkSeqNum::new(105);
    /// assert_eq!(b.signed_diff(a), 5);  // b is 5 ahead of a
    /// assert_eq!(a.signed_diff(b), -5); // a is 5 behind b
    /// ```
    #[inline]
    pub fn signed_diff(self, other: Self) -> i32 {
        let diff = (self.0 as i32) - (other.0 as i32);
        // The u16 space wraps, so we interpret distance using the "half-space" rule:
        // if |diff| > 32768, the shorter path is via the wrap boundary.
        // Normalize to [-32768, 32767] range (half the u16 space).
        if diff > 32767 {
            diff - 65536
        } else if diff < -32768 {
            diff + 65536
        } else {
            diff
        }
    }
}

impl core::fmt::Display for LinkSeqNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u16> for LinkSeqNum {
    #[inline]
    fn from(value: u16) -> Self {
        Self(value)
    }
}

impl From<LinkSeqNum> for u16 {
    #[inline]
    fn from(value: LinkSeqNum) -> Self {
        value.0
    }
}

/// 24-bit unsigned serial `(epoch << 16) | seqnum`.
///
/// Epoch 255 / seqnum 65535 is `0xFFFFFF`, the last valid tuple before
/// link-key rotation. Epoch MUST NOT wrap 255 -> 0.
pub const fn logical_counter(epoch: u8, seqnum: u16) -> u32 {
    ((epoch as u32) << 16) | (seqnum as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapping_increment() {
        let mut seq = LinkSeqNum::new(0xFFFE);
        assert_eq!(seq.get(), 0xFFFE);

        let old = seq.fetch_increment();
        assert_eq!(old.get(), 0xFFFE);
        assert_eq!(seq.get(), 0xFFFF);

        let old = seq.fetch_increment();
        assert_eq!(old.get(), 0xFFFF);
        assert_eq!(seq.get(), 0); // wrapped
    }

    #[test]
    fn signed_diff_forward() {
        let a = LinkSeqNum::new(100);
        let b = LinkSeqNum::new(105);
        assert_eq!(b.signed_diff(a), 5);
        assert_eq!(a.signed_diff(b), -5);
    }

    #[test]
    fn signed_diff_wrapping() {
        let a = LinkSeqNum::new(0xFFFE);
        let b = LinkSeqNum::new(0x0002);
        // b is 4 ahead of a (wrapped)
        assert_eq!(b.signed_diff(a), 4);
        assert_eq!(a.signed_diff(b), -4);
    }

    #[test]
    fn be_bytes_roundtrip() {
        let seq = LinkSeqNum::new(0x1234);
        let bytes = seq.to_be_bytes();
        assert_eq!(bytes, [0x12, 0x34]);
        assert_eq!(LinkSeqNum::from_be_bytes(bytes), seq);
    }

    #[test]
    fn twenty_four_bit_serial() {
        assert_eq!(logical_counter(5, 65535), 393_215);
        assert_eq!(logical_counter(6, 0), 393_216);
        assert_eq!(logical_counter(255, 65535), 0x00FF_FFFF);
        assert_eq!(LinkSeqNum::new(65535).with_epoch(5), 393_215);
        assert!(logical_counter(5, 65535) < logical_counter(6, 0));
        assert!(logical_counter(9, 65535) < logical_counter(10, 100));
    }

    #[test]
    fn conversion_traits() {
        let seq: LinkSeqNum = 42u16.into();
        assert_eq!(seq.get(), 42);

        let raw: u16 = seq.into();
        assert_eq!(raw, 42);
    }
}
