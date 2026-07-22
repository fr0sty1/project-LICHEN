//! OSCORE sender sequence number newtype.
//!
//! Wraps a u32 sequence number with OSCORE-specific semantics:
//! - Monotonically increasing (never wraps for security)
//! - Used for nonce derivation and replay protection
//!
//! The newtype provides type safety to prevent mixing OSCORE sequence
//! numbers with other u32 values or link-layer sequence numbers.

use zeroize::Zeroize;

/// OSCORE sender sequence number (u32, monotonic).
///
/// This is the Partial IV (PIV) included in OSCORE-protected messages.
/// Unlike link-layer sequence numbers, OSCORE sequences must never wrap
/// for the same security context - doing so would compromise security.
///
/// # Security
///
/// When `sender_seq` approaches `u32::MAX`, the context must be
/// renegotiated to prevent nonce reuse. The `is_near_exhaustion`
/// method checks for this condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Zeroize)]
#[repr(transparent)]
pub struct OscoreSeqNum(u32);

/// Threshold for sequence number exhaustion warning.
/// At 4 billion - 1000, warn the application to renegotiate.
const EXHAUSTION_THRESHOLD: u32 = u32::MAX - 1000;

impl OscoreSeqNum {
    /// Create a new OSCORE sequence number.
    #[inline]
    pub const fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get the raw u32 value.
    #[inline]
    pub const fn get(self) -> u32 {
        self.0
    }

    /// Increment by one, returning the new value.
    ///
    /// Returns `None` if the sequence number is at `u32::MAX` (would overflow).
    /// SECURITY: Callers must handle `None` by renegotiating the security context
    /// to prevent nonce reuse, which would compromise AES-CCM confidentiality.
    #[inline]
    #[must_use = "returns a new value; does not modify self"]
    pub const fn increment(self) -> Option<Self> {
        self.0.checked_add(1).map(Self)
    }

    /// Increment in place, returning the old value.
    ///
    /// Useful for the sender path where you want to use the current
    /// sequence number and advance to the next.
    ///
    /// Returns `None` if the sequence number is at `u32::MAX` (would overflow).
    /// SECURITY: Callers must handle `None` by renegotiating the security context
    /// to prevent nonce reuse, which would compromise AES-CCM confidentiality.
    #[inline]
    pub fn fetch_increment(&mut self) -> Option<Self> {
        let old = *self;
        *self = self.increment()?;
        Some(old)
    }

    /// Check if the sequence number is near exhaustion.
    ///
    /// Returns true when fewer than 1000 sequence numbers remain before
    /// overflow. The application should renegotiate the security context
    /// when this returns true.
    #[inline]
    pub const fn is_near_exhaustion(self) -> bool {
        self.0 >= EXHAUSTION_THRESHOLD
    }

    /// Encode as variable-length big-endian PIV (1-5 bytes).
    ///
    /// OSCORE uses the minimum number of bytes needed to represent the value.
    pub fn encode_piv(self, piv: &mut [u8; 5]) -> usize {
        let seq = self.0;
        if seq == 0 {
            piv[0] = 0;
            return 1;
        }

        let mut len = 0;
        let mut tmp = seq;
        while tmp > 0 {
            len += 1;
            tmp >>= 8;
        }

        let mut s = seq;
        for i in 0..len {
            piv[len - 1 - i] = (s & 0xFF) as u8;
            s >>= 8;
        }

        len
    }

    /// Decode from variable-length big-endian PIV.
    ///
    /// PIV values exceeding u32::MAX (i.e., PIV > 4 bytes with high bits set)
    /// saturate to u32::MAX rather than silently wrapping. Per RFC 8613 Section 5.2,
    /// PIV is at most 5 bytes, but only 4 bytes fit in a u32.
    pub fn from_piv(piv: &[u8]) -> Self {
        // Limit to 4 bytes to prevent overflow; extra bytes saturate to MAX
        if piv.len() > 4 {
            // Check if high bytes would cause overflow
            let high_bytes = &piv[..piv.len() - 4];
            if high_bytes.iter().any(|&b| b != 0) {
                return Self(u32::MAX);
            }
            // Use only the last 4 bytes
            let start = piv.len() - 4;
            return Self(u32::from_be_bytes([
                piv[start],
                piv[start + 1],
                piv[start + 2],
                piv[start + 3],
            ]));
        }
        Self(piv.iter().fold(0u32, |acc, &b| (acc << 8) | (b as u32)))
    }
}

impl core::fmt::Display for OscoreSeqNum {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl From<u32> for OscoreSeqNum {
    #[inline]
    fn from(value: u32) -> Self {
        Self(value)
    }
}

impl From<OscoreSeqNum> for u32 {
    #[inline]
    fn from(value: OscoreSeqNum) -> Self {
        value.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_operations() {
        let mut seq = OscoreSeqNum::new(0);
        assert_eq!(seq.get(), 0);

        let old = seq.fetch_increment().expect("should not overflow from 0");
        assert_eq!(old.get(), 0);
        assert_eq!(seq.get(), 1);
    }

    #[test]
    fn increment_at_max_returns_none() {
        let seq = OscoreSeqNum::new(u32::MAX);
        assert!(seq.increment().is_none());

        let mut seq_mut = OscoreSeqNum::new(u32::MAX);
        assert!(seq_mut.fetch_increment().is_none());
        // Value unchanged after failed increment
        assert_eq!(seq_mut.get(), u32::MAX);
    }

    #[test]
    fn increment_near_max_succeeds() {
        let seq = OscoreSeqNum::new(u32::MAX - 1);
        let next = seq.increment().expect("should succeed at MAX-1");
        assert_eq!(next.get(), u32::MAX);
    }

    #[test]
    fn exhaustion_detection() {
        let low = OscoreSeqNum::new(1000);
        assert!(!low.is_near_exhaustion());

        let high = OscoreSeqNum::new(EXHAUSTION_THRESHOLD);
        assert!(high.is_near_exhaustion());

        let max = OscoreSeqNum::new(u32::MAX);
        assert!(max.is_near_exhaustion());
    }

    #[test]
    fn piv_encode_decode() {
        let mut piv = [0u8; 5];

        let seq = OscoreSeqNum::new(0);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 0);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]), seq);

        let seq = OscoreSeqNum::new(1);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 1);
        assert_eq!(piv[0], 1);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]), seq);

        let seq = OscoreSeqNum::new(256);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 2);
        assert_eq!(&piv[..2], &[0x01, 0x00]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]), seq);

        let seq = OscoreSeqNum::new(0x123456);
        let len = seq.encode_piv(&mut piv);
        assert_eq!(len, 3);
        assert_eq!(&piv[..3], &[0x12, 0x34, 0x56]);
        assert_eq!(OscoreSeqNum::from_piv(&piv[..len]), seq);
    }

    #[test]
    fn conversion_traits() {
        let seq: OscoreSeqNum = 42u32.into();
        assert_eq!(seq.get(), 42);

        let raw: u32 = seq.into();
        assert_eq!(raw, 42);
    }
}
