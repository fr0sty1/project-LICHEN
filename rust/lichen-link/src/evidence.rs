//! Monotonic reception evidence shared by authenticated protocol layers.

#[cfg(all(feature = "schnorr", feature = "std"))]
use core::sync::atomic::AtomicU64;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use crate::{frame::AddrMode, LinkSeqNum};

// Supported embedded targets guarantee 32-bit atomics, but several do not
// provide AtomicU64. The public opaque representation remains u64 so this
// allocation detail does not leak across protocol layers.
static NEXT_CLOCK_DOMAIN: AtomicU32 = AtomicU32::new(1);
#[cfg(all(feature = "schnorr", feature = "std"))]
static NEXT_PEER_KEY_GENERATION: AtomicU64 = AtomicU64::new(1);

/// Opaque process-local identity of one installed peer-key generation.
///
/// The numeric value is deliberately private and non-serializable. Equality
/// is the only supported operation: revoke/reinstall of the same public key
/// receives a distinct value, allowing upper layers to bind state to the exact
/// trust-store generation instead of merely to key bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PeerKeyGeneration(u64);

/// Stable opaque identity of a peer-key installation in authenticated storage.
///
/// Unlike [`PeerKeyGeneration`], this value survives process restart.  Only
/// the link trust owner constructs it; protocol layers may compare or persist
/// the bytes but cannot manufacture a value from untrusted storage.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DurablePeerKeyGeneration([u8; 16]);

impl DurablePeerKeyGeneration {
    /// Stable bytes for an integrity-protected trust/fragmentation record.
    pub const fn as_bytes(self) -> [u8; 16] {
        self.0
    }

    /// Sentinel for unauthenticated raw/fuzz state; never owner-issued.
    #[doc(hidden)]
    pub const fn invalid_for_raw_codec() -> Self {
        Self([0; 16])
    }

    #[cfg(all(feature = "schnorr", feature = "std"))]
    pub(crate) fn from_owner_bytes(bytes: [u8; 16]) -> Option<Self> {
        if bytes == [0; 16] {
            None
        } else {
            Some(Self(bytes))
        }
    }

    /// Deterministic owner-issued value for capability tests.
    #[doc(hidden)]
    pub const fn from_test_value(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            let mut bytes = [0u8; 16];
            let encoded = value.to_be_bytes();
            let mut index = 0;
            while index < encoded.len() {
                bytes[8 + index] = encoded[index];
                index += 1;
            }
            Some(Self(bytes))
        }
    }
}

impl PeerKeyGeneration {
    #[cfg(all(feature = "schnorr", feature = "std"))]
    pub(crate) fn allocate() -> Option<Self> {
        NEXT_PEER_KEY_GENERATION
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .ok()
            .map(Self)
    }

    /// Sentinel reserved for unauthenticated codec/fuzz state. It can never
    /// equal an owner-issued production generation, all of which are nonzero.
    #[doc(hidden)]
    pub const fn invalid_for_raw_codec() -> Self {
        Self(0)
    }

    /// Construct deterministic opaque generation evidence for tests only.
    #[doc(hidden)]
    pub const fn from_test_value(value: u64) -> Option<Self> {
        if value == 0 {
            None
        } else {
            Some(Self(value))
        }
    }
}

/// Failure to allocate or advance a monotonic reception clock.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptClockError {
    /// Process-local clock-domain identifiers have been exhausted.
    DomainExhausted,
    /// The supplied timestamp moved backwards in this clock domain.
    ClockRegression,
    /// A receiver attempted to mix logical ticks, opaque platform ticks, and
    /// millisecond timestamps in one evidence domain.
    ClockModeMismatch,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptClockMode {
    Unset,
    OpaqueTicks,
    Millis,
    Logical,
}

/// Immutable timestamp captured at authenticated-frame receipt.
///
/// The domain identifier makes timestamps comparable only when they came from
/// the same receiver clock. Callers cannot construct this evidence directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceiptEvidence {
    clock_domain: u64,
    monotonic_ticks: u64,
    duration_millis: Option<u64>,
}

impl ReceiptEvidence {
    /// Opaque process-local clock-domain identifier.
    pub const fn clock_domain(&self) -> u64 {
        self.clock_domain
    }

    /// Timestamp in the receiver-defined monotonic tick unit.
    pub const fn monotonic_ticks(&self) -> u64 {
        self.monotonic_ticks
    }

    /// Monotonic milliseconds suitable for protocol duration calculations.
    ///
    /// Logical fallback receipts intentionally return `None`: a packet count
    /// is not a time unit and must never be used for a normative timeout.
    pub const fn monotonic_millis(&self) -> Option<u64> {
        self.duration_millis
    }

    /// Compare two receipt timestamps, rejecting foreign clock domains.
    pub const fn elapsed_since(&self, earlier: &Self) -> Option<u64> {
        if self.clock_domain != earlier.clock_domain {
            return None;
        }
        self.monotonic_ticks.checked_sub(earlier.monotonic_ticks)
    }

    /// Construct deterministic evidence for capability tests only.
    #[cfg(feature = "test-utils")]
    pub const fn from_test_parts(
        clock_domain: u64,
        monotonic_ticks: u64,
        duration_millis: Option<u64>,
    ) -> Self {
        Self {
            clock_domain,
            monotonic_ticks,
            duration_millis,
        }
    }
}

/// Owner of one no-std-capable monotonic reception clock domain.
#[derive(Debug)]
pub struct ReceiptClock {
    domain: u64,
    last_ticks: u64,
    mode: ReceiptClockMode,
}

impl ReceiptClock {
    /// Allocate a fresh, non-serializable-by-convention process-local domain.
    pub fn new() -> Result<Self, ReceiptClockError> {
        let domain = NEXT_CLOCK_DOMAIN
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                current.checked_add(1).filter(|next| *next != 0)
            })
            .map_err(|_| ReceiptClockError::DomainExhausted)?;
        Ok(Self {
            domain: u64::from(domain),
            last_ticks: 0,
            mode: ReceiptClockMode::Unset,
        })
    }

    fn select_mode(&mut self, requested: ReceiptClockMode) -> Result<(), ReceiptClockError> {
        match self.mode {
            ReceiptClockMode::Unset => {
                self.mode = requested;
                Ok(())
            }
            current if current == requested => Ok(()),
            _ => Err(ReceiptClockError::ClockModeMismatch),
        }
    }

    /// Capture a timestamp supplied by this receiver's monotonic platform clock.
    pub fn observe(&mut self, monotonic_ticks: u64) -> Result<ReceiptEvidence, ReceiptClockError> {
        self.select_mode(ReceiptClockMode::OpaqueTicks)?;
        if monotonic_ticks < self.last_ticks {
            return Err(ReceiptClockError::ClockRegression);
        }
        self.last_ticks = monotonic_ticks;
        Ok(ReceiptEvidence {
            clock_domain: self.domain,
            monotonic_ticks,
            duration_millis: None,
        })
    }

    /// Capture a platform monotonic timestamp expressed in milliseconds.
    pub fn observe_millis(
        &mut self,
        monotonic_millis: u64,
    ) -> Result<ReceiptEvidence, ReceiptClockError> {
        self.select_mode(ReceiptClockMode::Millis)?;
        if monotonic_millis < self.last_ticks {
            return Err(ReceiptClockError::ClockRegression);
        }
        self.last_ticks = monotonic_millis;
        Ok(ReceiptEvidence {
            clock_domain: self.domain,
            monotonic_ticks: monotonic_millis,
            duration_millis: Some(monotonic_millis),
        })
    }

    /// Advance the built-in logical fallback clock by one tick.
    pub fn next_logical(&mut self) -> Result<ReceiptEvidence, ReceiptClockError> {
        self.select_mode(ReceiptClockMode::Logical)?;
        let next = self
            .last_ticks
            .checked_add(1)
            .ok_or(ReceiptClockError::ClockRegression)?;
        self.last_ticks = next;
        Ok(ReceiptEvidence {
            clock_domain: self.domain,
            monotonic_ticks: next,
            duration_millis: None,
        })
    }
}

#[cfg(test)]
mod receipt_clock_tests {
    use super::*;

    #[test]
    fn logical_then_millis_fails_closed() {
        let mut clock = ReceiptClock::new().unwrap();
        clock.next_logical().unwrap();
        assert_eq!(
            clock.observe_millis(1),
            Err(ReceiptClockError::ClockModeMismatch)
        );
    }

    #[test]
    fn millis_then_logical_fails_closed() {
        let mut clock = ReceiptClock::new().unwrap();
        clock.observe_millis(1).unwrap();
        assert_eq!(
            clock.next_logical(),
            Err(ReceiptClockError::ClockModeMismatch)
        );
    }
}

/// Borrowed, owner-issued evidence for one link-authenticated frame.
///
/// Its fields are private and production constructors live in the link TCB.
/// Higher layers can therefore consume verified facts without accepting a
/// caller-assembled "verified" struct. Retirement flags keep the capability
/// revocable for as long as it is borrowed.
#[derive(Clone, Copy, Debug)]
pub struct AuthenticatedLinkFrame<'a> {
    payload: &'a [u8],
    destination: &'a [u8],
    destination_mode: AddrMode,
    signer: [u8; 32],
    signer_eui64: [u8; 8],
    epoch: u8,
    seqnum: LinkSeqNum,
    receipt: ReceiptEvidence,
    peer_key_generation: PeerKeyGeneration,
    durable_peer_key_generation: DurablePeerKeyGeneration,
    receiving_link_retired: &'a AtomicBool,
    peer_generation_retired: &'a AtomicBool,
}

impl<'a> AuthenticatedLinkFrame<'a> {
    #[allow(dead_code)]
    #[allow(clippy::too_many_arguments)]
    pub(crate) const fn new(
        payload: &'a [u8],
        destination: &'a [u8],
        destination_mode: AddrMode,
        signer: [u8; 32],
        signer_eui64: [u8; 8],
        epoch: u8,
        seqnum: LinkSeqNum,
        receipt: ReceiptEvidence,
        peer_key_generation: PeerKeyGeneration,
        durable_peer_key_generation: DurablePeerKeyGeneration,
        receiving_link_retired: &'a AtomicBool,
        peer_generation_retired: &'a AtomicBool,
    ) -> Self {
        Self {
            payload,
            destination,
            destination_mode,
            signer,
            signer_eui64,
            epoch,
            seqnum,
            receipt,
            peer_key_generation,
            durable_peer_key_generation,
            receiving_link_retired,
            peer_generation_retired,
        }
    }

    pub const fn payload(self) -> &'a [u8] {
        self.payload
    }
    pub const fn destination(self) -> &'a [u8] {
        self.destination
    }
    pub const fn destination_mode(self) -> AddrMode {
        self.destination_mode
    }
    pub const fn signer(self) -> [u8; 32] {
        self.signer
    }
    /// Canonical signer identifier carried by SI: the sender's EUI-64.
    pub const fn signer_eui64(self) -> [u8; 8] {
        self.signer_eui64
    }
    pub const fn epoch(self) -> u8 {
        self.epoch
    }
    pub const fn seqnum(self) -> LinkSeqNum {
        self.seqnum
    }
    pub const fn receipt(self) -> ReceiptEvidence {
        self.receipt
    }
    pub const fn peer_key_generation(self) -> PeerKeyGeneration {
        self.peer_key_generation
    }
    pub const fn durable_peer_key_generation(self) -> DurablePeerKeyGeneration {
        self.durable_peer_key_generation
    }

    pub fn is_current(self) -> bool {
        !self.receiving_link_retired.load(Ordering::Acquire)
            && !self.peer_generation_retired.load(Ordering::Acquire)
    }

    pub const fn authenticated_counter(self) -> u32 {
        ((self.epoch as u32) << 16) | self.seqnum.get() as u32
    }

    /// Test-only constructor used by no-std capability tests.
    #[cfg(feature = "test-utils")]
    #[allow(clippy::too_many_arguments)]
    pub fn from_test_parts(
        payload: &'a [u8],
        destination: &'a [u8],
        destination_mode: AddrMode,
        signer: [u8; 32],
        signer_eui64: [u8; 8],
        epoch: u8,
        seqnum: LinkSeqNum,
        receipt: ReceiptEvidence,
        peer_key_generation: PeerKeyGeneration,
        durable_peer_key_generation: DurablePeerKeyGeneration,
        receiving_link_retired: &'a AtomicBool,
        peer_generation_retired: &'a AtomicBool,
    ) -> Self {
        Self::new(
            payload,
            destination,
            destination_mode,
            signer,
            signer_eui64,
            epoch,
            seqnum,
            receipt,
            peer_key_generation,
            durable_peer_key_generation,
            receiving_link_retired,
            peer_generation_retired,
        )
    }
}

impl Default for ReceiptClock {
    fn default() -> Self {
        Self::new().expect("receipt clock-domain identifiers exhausted")
    }
}
