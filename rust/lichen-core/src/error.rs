//! Common error types shared across LICHEN crates.
//!
//! Re-exports structured error types from lichen-ipv6 for consistent
//! error messages and proper error chaining across the stack.

// Re-export error types from lichen-ipv6 for use across the workspace.
pub use lichen_ipv6::{BufferTooSmall, TooShort};

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::format;

    #[test]
    fn too_short_display() {
        let err = TooShort::new(10, 5);
        assert_eq!(
            format!("{}", err),
            "buffer too short: expected 10 bytes, got 5"
        );
    }

    #[test]
    fn buffer_too_small_display() {
        let err = BufferTooSmall::new(100, 50);
        assert_eq!(
            format!("{}", err),
            "output buffer too small: need 100 bytes, have 50"
        );
    }
}
