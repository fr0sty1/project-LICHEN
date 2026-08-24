//! Datagram channel abstraction for CoAP transport.
//!
//! Provides the [`DatagramChannel`] trait for bidirectional, host-addressed
//! datagram links with congestion-aware transmission. This is the Rust
//! equivalent of Python's `DatagramChannel` ABC.
//!
//! # Example
//!
//! ```
//! use lichen_core::transport::{DatagramChannel, CongestionError};
//! use lichen_core::duty_cycle::{CongestionLevel, CongestionState};
//! use lichen_core::tx_queue::TxPriority;
//!
//! struct LoopbackChannel;
//!
//! impl DatagramChannel for LoopbackChannel {
//!     fn send_datagram(
//!         &self,
//!         data: &[u8],
//!         dest: &str,
//!         priority: TxPriority,
//!         check_congestion: bool,
//!     ) -> Result<(), CongestionError> {
//!         // In a real implementation, this would send the datagram
//!         Ok(())
//!     }
//! }
//!
//! let channel = LoopbackChannel;
//! assert!(channel.send_datagram(b"hello", "::1", TxPriority::Normal, true).is_ok());
//! ```

use core::fmt;

use crate::duty_cycle::{CongestionLevel, CongestionState};
use crate::tx_queue::TxPriority;

/// Error returned when transmission is blocked due to duty cycle congestion.
///
/// Per spec 07 section 10.2.3, congested nodes must shed traffic:
/// - ELEVATED: delay non-urgent (NORMAL/BULK)
/// - CRITICAL: only SOS/routing
/// - EXHAUSTED: stop all TX
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CongestionError {
    /// Current congestion level.
    pub level: CongestionLevel,
    /// Priority of the blocked transmission.
    pub priority: TxPriority,
    /// Estimated time until transmission may be allowed (ms), or None if unknown.
    pub retry_after_ms: Option<u32>,
}

impl CongestionError {
    /// Create a new congestion error.
    #[inline]
    pub const fn new(
        level: CongestionLevel,
        priority: TxPriority,
        retry_after_ms: Option<u32>,
    ) -> Self {
        Self {
            level,
            priority,
            retry_after_ms,
        }
    }
}

impl fmt::Display for CongestionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "transmission blocked at {:?} congestion (priority {:?})",
            self.level, self.priority
        )
    }
}

impl core::error::Error for CongestionError {}

/// Check if a transmission is allowed at the given congestion level.
///
/// Implements spec 07 section 10.2.3:
/// - NORMAL (<50%): all traffic allowed
/// - ELEVATED (50-80%): delay non-urgent (NORMAL/BULK), allow SOS/ROUTING/URGENT
/// - CRITICAL (80-95%): only SOS/ROUTING
/// - EXHAUSTED (>95%): stop all TX
///
/// # Arguments
///
/// * `level` - Current duty cycle congestion level.
/// * `priority` - Priority of the transmission (SOS=highest, BULK=lowest).
///
/// # Returns
///
/// `true` if transmission is allowed, `false` if it should be blocked.
#[inline]
pub const fn check_congestion_allows(level: CongestionLevel, priority: TxPriority) -> bool {
    match level {
        CongestionLevel::Normal => true,
        CongestionLevel::Elevated => {
            // Allow SOS, ROUTING, URGENT (values 0-2)
            (priority as u8) <= (TxPriority::Urgent as u8)
        }
        CongestionLevel::Critical => {
            // Only SOS, ROUTING (values 0-1)
            (priority as u8) <= (TxPriority::Routing as u8)
        }
        CongestionLevel::Exhausted => false,
    }
}

/// A bidirectional, host-addressed datagram link for CoAP messages.
///
/// Implementations providing duty-cycle-constrained links should override
/// [`congestion_level`](DatagramChannel::congestion_level) and optionally
/// [`retry_after_ms`](DatagramChannel::retry_after_ms) to enable
/// congestion-aware transmission.
///
/// This trait is the Rust equivalent of Python's `DatagramChannel` ABC,
/// providing uniform priority propagation for CoAP over LICHEN.
pub trait DatagramChannel {
    /// Send `data` to the endpoint identified by `dest`.
    ///
    /// # Arguments
    ///
    /// * `data` - Datagram payload to send.
    /// * `dest` - Destination endpoint identifier (typically an IPv6 address).
    /// * `priority` - Transmission priority for congestion checking.
    /// * `check_congestion` - If true, check congestion before sending.
    ///
    /// # Errors
    ///
    /// Returns `CongestionError` if `check_congestion` is true and the
    /// current congestion level blocks this priority.
    fn send_datagram(
        &self,
        data: &[u8],
        dest: &str,
        priority: TxPriority,
        check_congestion: bool,
    ) -> Result<(), CongestionError>;

    /// Return current duty cycle congestion level.
    ///
    /// Override in channels with actual duty cycle tracking.
    /// Default implementation returns NORMAL (no congestion).
    #[inline]
    fn congestion_level(&self) -> CongestionLevel {
        CongestionLevel::Normal
    }

    /// Return estimated time until duty cycle budget refills (ms).
    ///
    /// Override in channels with actual duty cycle tracking.
    /// Default implementation returns None (unknown).
    #[inline]
    fn retry_after_ms(&self) -> Option<u32> {
        None
    }

    /// Return atomic snapshot of congestion level and retry delay.
    ///
    /// This method provides an atomic read of both congestion_level and
    /// retry_after_ms to avoid race conditions when these values are read
    /// separately in concurrent environments.
    ///
    /// Override in channels with actual duty cycle tracking. The default
    /// implementation reads the methods separately (safe when they share
    /// underlying state or are constants).
    #[inline]
    fn congestion_state(&self) -> CongestionState {
        CongestionState {
            level: self.congestion_level(),
            retry_after_ms: self.retry_after_ms(),
        }
    }

    /// Check if transmission is blocked at current congestion level.
    ///
    /// Implements spec 07 section 10.2.3 congestion rules:
    /// - NORMAL: all traffic allowed
    /// - ELEVATED: P0-P2 only (delay non-urgent)
    /// - CRITICAL: P0-P1 only (SOS/routing)
    /// - EXHAUSTED: block all
    ///
    /// # Arguments
    ///
    /// * `priority` - Transmission priority to check.
    ///
    /// # Errors
    ///
    /// Returns `CongestionError` if transmission is blocked.
    #[inline]
    fn check_congestion_for(&self, priority: TxPriority) -> Result<(), CongestionError> {
        let state = self.congestion_state();
        if check_congestion_allows(state.level, priority) {
            Ok(())
        } else {
            Err(CongestionError::new(
                state.level,
                priority,
                state.retry_after_ms,
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_congestion_normal_allows_all() {
        assert!(check_congestion_allows(
            CongestionLevel::Normal,
            TxPriority::Sos
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Normal,
            TxPriority::Routing
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Normal,
            TxPriority::Urgent
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Normal,
            TxPriority::Normal
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Normal,
            TxPriority::Bulk
        ));
    }

    #[test]
    fn check_congestion_elevated_blocks_low_priority() {
        assert!(check_congestion_allows(
            CongestionLevel::Elevated,
            TxPriority::Sos
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Elevated,
            TxPriority::Routing
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Elevated,
            TxPriority::Urgent
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Elevated,
            TxPriority::Normal
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Elevated,
            TxPriority::Bulk
        ));
    }

    #[test]
    fn check_congestion_critical_only_sos_routing() {
        assert!(check_congestion_allows(
            CongestionLevel::Critical,
            TxPriority::Sos
        ));
        assert!(check_congestion_allows(
            CongestionLevel::Critical,
            TxPriority::Routing
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Critical,
            TxPriority::Urgent
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Critical,
            TxPriority::Normal
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Critical,
            TxPriority::Bulk
        ));
    }

    #[test]
    fn check_congestion_exhausted_blocks_all() {
        assert!(!check_congestion_allows(
            CongestionLevel::Exhausted,
            TxPriority::Sos
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Exhausted,
            TxPriority::Routing
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Exhausted,
            TxPriority::Urgent
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Exhausted,
            TxPriority::Normal
        ));
        assert!(!check_congestion_allows(
            CongestionLevel::Exhausted,
            TxPriority::Bulk
        ));
    }

    #[test]
    fn congestion_error_display() {
        extern crate std;
        let err = CongestionError::new(CongestionLevel::Critical, TxPriority::Normal, Some(5000));
        let msg = std::format!("{}", err);
        assert!(msg.contains("Critical"));
        assert!(msg.contains("Normal"));
    }

    struct TestChannel {
        level: CongestionLevel,
        retry_ms: Option<u32>,
    }

    impl DatagramChannel for TestChannel {
        fn send_datagram(
            &self,
            _data: &[u8],
            _dest: &str,
            priority: TxPriority,
            check_congestion: bool,
        ) -> Result<(), CongestionError> {
            if check_congestion {
                self.check_congestion_for(priority)?;
            }
            Ok(())
        }

        fn congestion_level(&self) -> CongestionLevel {
            self.level
        }

        fn retry_after_ms(&self) -> Option<u32> {
            self.retry_ms
        }
    }

    #[test]
    fn datagram_channel_default_congestion() {
        struct DefaultChannel;
        impl DatagramChannel for DefaultChannel {
            fn send_datagram(
                &self,
                _data: &[u8],
                _dest: &str,
                _priority: TxPriority,
                _check_congestion: bool,
            ) -> Result<(), CongestionError> {
                Ok(())
            }
        }

        let ch = DefaultChannel;
        assert_eq!(ch.congestion_level(), CongestionLevel::Normal);
        assert_eq!(ch.retry_after_ms(), None);
        let state = ch.congestion_state();
        assert_eq!(state.level, CongestionLevel::Normal);
        assert_eq!(state.retry_after_ms, None);
    }

    #[test]
    fn datagram_channel_check_congestion_for() {
        let ch = TestChannel {
            level: CongestionLevel::Critical,
            retry_ms: Some(1000),
        };

        // SOS should pass
        assert!(ch.check_congestion_for(TxPriority::Sos).is_ok());

        // Normal should fail
        let err = ch.check_congestion_for(TxPriority::Normal).unwrap_err();
        assert_eq!(err.level, CongestionLevel::Critical);
        assert_eq!(err.priority, TxPriority::Normal);
        assert_eq!(err.retry_after_ms, Some(1000));
    }

    #[test]
    fn datagram_channel_send_with_congestion_check() {
        let ch = TestChannel {
            level: CongestionLevel::Elevated,
            retry_ms: None,
        };

        // Urgent should pass with congestion check
        assert!(ch
            .send_datagram(b"test", "::1", TxPriority::Urgent, true)
            .is_ok());

        // Normal should fail with congestion check
        assert!(ch
            .send_datagram(b"test", "::1", TxPriority::Normal, true)
            .is_err());

        // Normal should pass without congestion check
        assert!(ch
            .send_datagram(b"test", "::1", TxPriority::Normal, false)
            .is_ok());
    }

    #[test]
    fn datagram_channel_congestion_state() {
        let ch = TestChannel {
            level: CongestionLevel::Elevated,
            retry_ms: Some(5000),
        };

        let state = ch.congestion_state();
        assert_eq!(state.level, CongestionLevel::Elevated);
        assert_eq!(state.retry_after_ms, Some(5000));
    }
}
