//! LOADng control message codecs (spec section 10, appendix B2).
//!
//! LOADng provides reactive peer-to-peer route discovery. Messages are ICMPv6
//! type 158, with code selecting RREQ (0), RREP (1), RERR (2).
//!
//! # Handler-level validation (beyond codec parsing)
//!
//! Routers implementing LOADng MUST apply these checks in addition to codec
//! validation:
//!
//! - **RREQ hop_limit rejection**: RREQs with `hop_limit > INITIAL_HOP_LIMIT`
//!   must be handler-rejected with no state change. The cost derivation
//!   `INITIAL_HOP_LIMIT - hop_limit` goes negative for expanding-ring values
//!   5..15, so until messages carry traversed-hop data they must be dropped.
//!   This is distinct from codec-level rejection of `hop_limit > MAX_HOP_LIMIT`.
//!
//! - **RREP proxy-hint downgrade**: RREPs with [`RREP_FLAG_PROXY`] set are
//!   non-authoritative hints: their sequence claims are unverified and may only
//!   bootstrap a route when no usable knowledge of the destination exists. They
//!   must never displace or upgrade an existing route/gradient entry.
//!
//! - **RREP forwarding gates**: Before forwarding an RREP, routers must:
//!   1. Check a seen-window to suppress duplicate/stale replays within the
//!      suppression window (same originator+destination+seq or older seq).
//!   2. Apply a freshness gate: only forward if the RREP carries information
//!      at least as fresh as the local route cache (RFC 3561 section 6.2).

use crate::addr::Ipv6Addr;
use core::marker::PhantomData;

/// ICMPv6 type for LOADng messages.
pub const LOADNG_ICMPV6_TYPE: u8 = 158;

/// Initial hop limit for expanding ring search.
pub const INITIAL_HOP_LIMIT: u8 = 4;

/// Maximum hop limit.
pub const MAX_HOP_LIMIT: u8 = 15;

/// Half the 16-bit sequence space used by RFC 1982 serial comparison.
pub const SEQ_HALF: u16 = 0x8000;

/// Return true if `incoming` is fresher than `existing`.
///
/// Equal values are not fresher. The half-range boundary
/// (`incoming.wrapping_sub(existing) == SEQ_HALF`) is not fresher.
pub fn seq_is_fresher(existing: u16, incoming: u16) -> bool {
    if existing == incoming {
        return false;
    }
    incoming.wrapping_sub(existing) < SEQ_HALF
}

/// Expanding ring hop limits: [4, 8, 15].
pub const EXPANDING_RING: [u8; 3] = [4, 8, 15];

/// RREP flags bit 0: proxy/intermediate reply indicator.
///
/// Set by routers answering from a cached gradient instead of being the actual
/// destination. Receivers MUST treat flagged replies as non-authoritative hints:
/// unverified sequence claims that may bootstrap a route for a destination with
/// no existing usable entry, but must never replace or upgrade existing knowledge.
/// See module-level docs for handler requirements.
pub const RREP_FLAG_PROXY: u8 = 0x01;

/// LOADng ICMPv6 codes.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadngCode {
    Rreq = 0,
    Rrep = 1,
    Rerr = 2,
}

impl LoadngCode {
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Rreq),
            1 => Some(Self::Rrep),
            2 => Some(Self::Rerr),
            _ => None,
        }
    }
}

/// RERR error code (spec 10.6).
///
/// Only 0 and 1 are assigned. Any other wire value is preserved verbatim as
/// [`RerrCode::Other`] so codes from future protocol revisions round-trip
/// instead of failing to parse (canonical vectors include error_code = 255).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RerrCode {
    /// General/unspecified failure (wire value 0).
    Unspecified,
    /// No route available to the unreachable destination (wire value 1).
    NoRoute,
    /// Unassigned wire value, carried verbatim for round-trip fidelity.
    Other(u8),
}

impl From<u8> for RerrCode {
    fn from(v: u8) -> Self {
        match v {
            0 => Self::Unspecified,
            1 => Self::NoRoute,
            other => Self::Other(other),
        }
    }
}

impl From<RerrCode> for u8 {
    fn from(code: RerrCode) -> Self {
        match code {
            RerrCode::Unspecified => 0,
            RerrCode::NoRoute => 1,
            RerrCode::Other(v) => v,
        }
    }
}

use crate::error::{BufferTooSmall, TooShort};

/// LOADng message parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LoadngError {
    TooShort(TooShort),
    BufferTooSmall(BufferTooSmall),
    UnknownCode(u8),
    /// Received RREQ hop_limit or RREP hop_count above [`MAX_HOP_LIMIT`].
    HopLimitExceeded {
        /// The out-of-range value from the wire.
        got: u8,
    },
    InvalidDiscoveryTransition {
        from: RouteDiscoveryState,
        to: RouteDiscoveryState,
    },
    InvalidDiscoveryReply,
}

impl core::fmt::Display for LoadngError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "LOADng {}", e),
            Self::BufferTooSmall(e) => write!(f, "LOADng {}", e),
            Self::UnknownCode(c) => write!(f, "unknown LOADng code: {}", c),
            Self::HopLimitExceeded { got } => write!(
                f,
                "LOADng hop value {} exceeds MAX_HOP_LIMIT {}",
                got, MAX_HOP_LIMIT
            ),
            Self::InvalidDiscoveryTransition { from, to } => {
                write!(
                    f,
                    "invalid LOADng discovery transition: {:?} -> {:?}",
                    from, to
                )
            }
            Self::InvalidDiscoveryReply => write!(f, "invalid LOADng discovery reply"),
        }
    }
}

impl core::error::Error for LoadngError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for LoadngError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for LoadngError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

// RREQ/RREP fixed length: flags(1) + hop(1) + seq(2) + orig(16) + dest(16) = 36
const RREQ_RREP_LEN: usize = 36;
// RERR fixed length: flags(1) + error_code(1) + unreachable(16) = 18
const RERR_LEN: usize = 18;

/// Route Request, flooded toward a destination (spec 10.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rreq {
    pub originator: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub seq_num: u16,
    pub hop_limit: u8,
    pub flags: u8,
}

/// Runtime route-discovery state for dynamic checks and observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteDiscoveryState {
    Idle,
    Searching,
    Replied,
    Failed,
}

impl RouteDiscoveryState {
    /// Whether this transition is allowed by the LOADng discovery state machine.
    pub const fn can_transition_to(self, next: Self) -> bool {
        match (self, next) {
            (Self::Idle, Self::Searching) => true,
            (Self::Searching, Self::Searching | Self::Replied | Self::Failed) => true,
            (Self::Replied, _) | (Self::Failed, _) => false,
            _ => false,
        }
    }

    /// Validate a runtime transition.
    pub fn transition_to(self, next: Self) -> Result<Self, LoadngError> {
        if self.can_transition_to(next) {
            Ok(next)
        } else {
            Err(LoadngError::InvalidDiscoveryTransition {
                from: self,
                to: next,
            })
        }
    }
}

/// Marker for a route discovery that has not sent its first RREQ.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Idle;

/// Marker for a route discovery that is sending expanding-ring RREQs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Searching;

/// Marker for a route discovery that received a matching RREP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Replied;

/// Marker for a route discovery that exhausted all expanding rings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Failed;

pub trait DiscoveryMarker {
    const STATE: RouteDiscoveryState;
}

impl DiscoveryMarker for Idle {
    const STATE: RouteDiscoveryState = RouteDiscoveryState::Idle;
}

impl DiscoveryMarker for Searching {
    const STATE: RouteDiscoveryState = RouteDiscoveryState::Searching;
}

impl DiscoveryMarker for Replied {
    const STATE: RouteDiscoveryState = RouteDiscoveryState::Replied;
}

impl DiscoveryMarker for Failed {
    const STATE: RouteDiscoveryState = RouteDiscoveryState::Failed;
}

/// Compile-time typed LOADng route discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteDiscovery<S> {
    originator: Ipv6Addr,
    destination: Ipv6Addr,
    seq_num: u16,
    ring_index: usize,
    _state: PhantomData<S>,
}

impl<S: DiscoveryMarker> RouteDiscovery<S> {
    /// Current dynamic state.
    pub const fn state(&self) -> RouteDiscoveryState {
        S::STATE
    }

    /// Originator address used in RREQs.
    pub const fn originator(&self) -> Ipv6Addr {
        self.originator
    }

    /// Destination address being discovered.
    pub const fn destination(&self) -> Ipv6Addr {
        self.destination
    }

    /// Sequence number carried by this discovery.
    pub const fn seq_num(&self) -> u16 {
        self.seq_num
    }

    /// Current expanding-ring index.
    pub const fn ring_index(&self) -> usize {
        self.ring_index
    }
}

impl RouteDiscovery<Idle> {
    /// Create an idle route discovery.
    pub const fn new(originator: Ipv6Addr, destination: Ipv6Addr, seq_num: u16) -> Self {
        Self {
            originator,
            destination,
            seq_num,
            ring_index: 0,
            _state: PhantomData,
        }
    }

    /// Start discovery and emit the first expanding-ring RREQ.
    /// Typestate: Idle -> Searching (enforced by type signature)
    pub fn start(self) -> (RouteDiscovery<Searching>, Rreq) {
        let searching = RouteDiscovery {
            originator: self.originator,
            destination: self.destination,
            seq_num: self.seq_num,
            ring_index: 0,
            _state: PhantomData,
        };
        let rreq = searching.rreq();
        (searching, rreq)
    }
}

impl RouteDiscovery<Searching> {
    /// Build the RREQ for the current expanding ring.
    pub fn rreq(&self) -> Rreq {
        Rreq {
            originator: self.originator,
            destination: self.destination,
            seq_num: self.seq_num,
            hop_limit: EXPANDING_RING[self.ring_index],
            flags: 0,
        }
    }

    /// Advance to the next expanding ring or fail if all rings are exhausted.
    /// Typestate: Searching -> Searching (self-loop, enforced by type signature)
    pub fn advance_ring(self) -> Result<(Self, Rreq), RouteDiscovery<Failed>> {
        if self.ring_index + 1 >= EXPANDING_RING.len() {
            return Err(self.fail());
        }
        let next = Self {
            ring_index: self.ring_index + 1,
            ..self
        };
        let rreq = next.rreq();
        Ok((next, rreq))
    }

    /// Mark discovery failed.
    /// Typestate: Searching -> Failed (enforced by type signature)
    pub fn fail(self) -> RouteDiscovery<Failed> {
        RouteDiscovery {
            originator: self.originator,
            destination: self.destination,
            seq_num: self.seq_num,
            ring_index: self.ring_index,
            _state: PhantomData,
        }
    }

    /// Accept a matching RREP and move to the terminal replied state.
    /// Typestate: Searching -> Replied (enforced by type signature)
    pub fn receive_rrep(self, rrep: Rrep) -> Result<RouteDiscovery<Replied>, LoadngError> {
        if rrep.originator != self.destination
            || rrep.destination != self.originator
            || rrep.seq_num != self.seq_num
        {
            return Err(LoadngError::InvalidDiscoveryReply);
        }
        Ok(RouteDiscovery {
            originator: self.originator,
            destination: self.destination,
            seq_num: self.seq_num,
            ring_index: self.ring_index,
            _state: PhantomData,
        })
    }
}

impl Rreq {
    /// Parse RREQ from ICMPv6 body (after type/code/checksum).
    ///
    /// Rejects hop_limit values above [`MAX_HOP_LIMIT`]: a compliant node
    /// never emits one, and accepting them would let a single forged RREQ
    /// propagate far beyond the protocol's flood bound.
    pub fn from_bytes(data: &[u8]) -> Result<Self, LoadngError> {
        if data.len() < RREQ_RREP_LEN {
            return Err(TooShort::new(RREQ_RREP_LEN, data.len()).into());
        }
        let hop_limit = data[1];
        if hop_limit > MAX_HOP_LIMIT {
            return Err(LoadngError::HopLimitExceeded { got: hop_limit });
        }
        Ok(Self {
            flags: data[0],
            hop_limit,
            seq_num: u16::from_be_bytes([data[2], data[3]]),
            originator: Ipv6Addr(data[4..20].try_into().unwrap()),
            destination: Ipv6Addr(data[20..36].try_into().unwrap()),
        })
    }

    /// Serialize to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        if out.len() < RREQ_RREP_LEN {
            return Err(BufferTooSmall::new(RREQ_RREP_LEN, out.len()).into());
        }
        out[0] = self.flags;
        out[1] = self.hop_limit;
        out[2..4].copy_from_slice(&self.seq_num.to_be_bytes());
        out[4..20].copy_from_slice(&self.originator.0);
        out[20..36].copy_from_slice(&self.destination.0);
        Ok(RREQ_RREP_LEN)
    }

    /// Decrement hop limit. Returns None if already zero.
    pub fn with_decremented_hop_limit(self) -> Option<Self> {
        if self.hop_limit == 0 {
            None
        } else {
            Some(Self {
                hop_limit: self.hop_limit - 1,
                ..self
            })
        }
    }
}

/// Route Reply, unicast back along reverse path (spec 10.4).
///
/// The `flags` field bit 0 ([`RREP_FLAG_PROXY`]) distinguishes authoritative
/// replies (from the actual destination, flags=0) from proxy/intermediate
/// replies (from a router using a cached gradient, flags=0x01). Receivers must
/// apply proxy-hint downgrade semantics; see module-level docs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rrep {
    pub originator: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub seq_num: u16,
    pub hop_count: u8,
    pub flags: u8,
}

impl Rrep {
    /// Parse RREP from ICMPv6 body.
    ///
    /// Rejects hop_count values above [`MAX_HOP_LIMIT`]: a compliant RREP
    /// traverses at most MAX_HOP_LIMIT hops, so larger values are malformed
    /// or forged. Clamping would still admit the packet with a rewritten
    /// route metric; rejecting keeps it out of the gradient table.
    pub fn from_bytes(data: &[u8]) -> Result<Self, LoadngError> {
        if data.len() < RREQ_RREP_LEN {
            return Err(TooShort::new(RREQ_RREP_LEN, data.len()).into());
        }
        let hop_count = data[1];
        if hop_count > MAX_HOP_LIMIT {
            return Err(LoadngError::HopLimitExceeded { got: hop_count });
        }
        Ok(Self {
            flags: data[0],
            hop_count,
            seq_num: u16::from_be_bytes([data[2], data[3]]),
            originator: Ipv6Addr(data[4..20].try_into().unwrap()),
            destination: Ipv6Addr(data[20..36].try_into().unwrap()),
        })
    }

    /// Serialize to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        if out.len() < RREQ_RREP_LEN {
            return Err(BufferTooSmall::new(RREQ_RREP_LEN, out.len()).into());
        }
        out[0] = self.flags;
        out[1] = self.hop_count;
        out[2..4].copy_from_slice(&self.seq_num.to_be_bytes());
        out[4..20].copy_from_slice(&self.originator.0);
        out[20..36].copy_from_slice(&self.destination.0);
        Ok(RREQ_RREP_LEN)
    }

    /// Increment hop count. Returns None if would exceed MAX_HOP_LIMIT.
    pub fn with_incremented_hop_count(self) -> Option<Self> {
        if self.hop_count >= MAX_HOP_LIMIT {
            None
        } else {
            Some(Self {
                hop_count: self.hop_count + 1,
                ..self
            })
        }
    }

    /// Check if this is a proxy/intermediate reply (not from the actual destination).
    ///
    /// Proxy replies carry unverified sequence claims and must be treated as
    /// non-authoritative hints: they may bootstrap a route when no usable
    /// knowledge exists, but must never replace or upgrade existing entries.
    #[inline]
    pub const fn is_proxy(&self) -> bool {
        self.flags & RREP_FLAG_PROXY != 0
    }
}

/// Route Error, sent when a link fails (spec 10.6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rerr {
    pub unreachable: Ipv6Addr,
    pub error_code: RerrCode,
    pub flags: u8,
}

impl Rerr {
    /// Parse RERR from ICMPv6 body.
    ///
    /// Assigned codes decode to their [`RerrCode`] variants; unassigned
    /// wire values are preserved as [`RerrCode::Other`] (see that type).
    pub fn from_bytes(data: &[u8]) -> Result<Self, LoadngError> {
        if data.len() < RERR_LEN {
            return Err(TooShort::new(RERR_LEN, data.len()).into());
        }
        Ok(Self {
            flags: data[0],
            error_code: RerrCode::from(data[1]),
            unreachable: Ipv6Addr(data[2..18].try_into().unwrap()),
        })
    }

    /// Serialize to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        if out.len() < RERR_LEN {
            return Err(BufferTooSmall::new(RERR_LEN, out.len()).into());
        }
        out[0] = self.flags;
        out[1] = self.error_code.into();
        out[2..18].copy_from_slice(&self.unreachable.0);
        Ok(RERR_LEN)
    }
}

/// Unified LOADng message enum.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadngMessage {
    Rreq(Rreq),
    Rrep(Rrep),
    Rerr(Rerr),
}

impl LoadngMessage {
    /// Parse from ICMPv6 code and body.
    pub fn from_icmpv6(code: u8, body: &[u8]) -> Result<Self, LoadngError> {
        match LoadngCode::from_u8(code) {
            Some(LoadngCode::Rreq) => Ok(Self::Rreq(Rreq::from_bytes(body)?)),
            Some(LoadngCode::Rrep) => Ok(Self::Rrep(Rrep::from_bytes(body)?)),
            Some(LoadngCode::Rerr) => Ok(Self::Rerr(Rerr::from_bytes(body)?)),
            None => Err(LoadngError::UnknownCode(code)),
        }
    }

    /// ICMPv6 code for this message.
    pub fn code(&self) -> u8 {
        match self {
            Self::Rreq(_) => LoadngCode::Rreq as u8,
            Self::Rrep(_) => LoadngCode::Rrep as u8,
            Self::Rerr(_) => LoadngCode::Rerr as u8,
        }
    }

    /// Serialize body to buffer. Returns bytes written.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, LoadngError> {
        match self {
            Self::Rreq(m) => m.write_to(out),
            Self::Rrep(m) => m.write_to(out),
            Self::Rerr(m) => m.write_to(out),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
    }

    #[test]
    fn rreq_roundtrip() {
        let rreq = Rreq {
            originator: ll(1),
            destination: ll(2),
            seq_num: 0x1234,
            hop_limit: 8,
            flags: 0,
        };
        let mut buf = [0u8; 64];
        let n = rreq.write_to(&mut buf).unwrap();
        assert_eq!(n, 36);

        let parsed = Rreq::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.originator, ll(1));
        assert_eq!(parsed.destination, ll(2));
        assert_eq!(parsed.seq_num, 0x1234);
        assert_eq!(parsed.hop_limit, 8);
    }

    #[test]
    fn rrep_roundtrip() {
        let rrep = Rrep {
            originator: ll(2),
            destination: ll(1),
            seq_num: 0x5678,
            hop_count: 3,
            flags: 0,
        };
        let mut buf = [0u8; 64];
        let n = rrep.write_to(&mut buf).unwrap();
        assert_eq!(n, 36);

        let parsed = Rrep::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.originator, ll(2));
        assert_eq!(parsed.destination, ll(1));
        assert_eq!(parsed.seq_num, 0x5678);
        assert_eq!(parsed.hop_count, 3);
    }

    #[test]
    fn rerr_roundtrip() {
        let rerr = Rerr {
            unreachable: ll(3),
            error_code: RerrCode::NoRoute,
            flags: 0,
        };
        let mut buf = [0u8; 32];
        let n = rerr.write_to(&mut buf).unwrap();
        assert_eq!(n, 18);

        let parsed = Rerr::from_bytes(&buf[..n]).unwrap();
        assert_eq!(parsed.unreachable, ll(3));
        assert_eq!(parsed.error_code, RerrCode::NoRoute);
    }

    #[test]
    fn rerr_code_wire_roundtrip_all_values() {
        // Oracle: wire identity. For every possible code byte the parsed
        // RerrCode must reserialize to the exact original bytes.
        for b in 0..=u8::MAX {
            let expected = RerrCode::from(b);
            match expected {
                RerrCode::Unspecified => assert_eq!(b, 0),
                RerrCode::NoRoute => assert_eq!(b, 1),
                RerrCode::Other(v) => {
                    assert!(b >= 2);
                    assert_eq!(v, b);
                }
            }
            let mut buf = [0u8; RERR_LEN];
            buf[1] = b;
            buf[2..18].copy_from_slice(&ll(3).0);
            let parsed = Rerr::from_bytes(&buf).unwrap();
            assert_eq!(parsed.error_code, expected);

            let mut out = [0u8; RERR_LEN];
            let n = parsed.write_to(&mut out).unwrap();
            assert_eq!(n, RERR_LEN);
            assert_eq!(out, buf, "code {} did not round-trip", b);
        }
    }

    #[test]
    fn rerr_canonical_vectors() {
        // From test/vectors/loadng_messages.json.
        let basic: [u8; 18] = hex("000102001122334455660011223344556609");
        let parsed = Rerr::from_bytes(&basic).unwrap();
        assert_eq!(parsed.error_code, RerrCode::NoRoute);
        assert_eq!(parsed.flags, 0);

        let max_code: [u8; 18] = hex("00ff02001122334455660011223344556609");
        let parsed = Rerr::from_bytes(&max_code).unwrap();
        assert_eq!(parsed.error_code, RerrCode::Other(255));

        let nonzero_flags: [u8; 18] = hex("800202001122334455660011223344556609");
        let parsed = Rerr::from_bytes(&nonzero_flags).unwrap();
        assert_eq!(parsed.error_code, RerrCode::Other(2));
        assert_eq!(parsed.flags, 0x80);

        let mut out = [0u8; RERR_LEN];
        let n = parsed.write_to(&mut out).unwrap();
        assert_eq!(&out[..n], &nonzero_flags[..]);
    }

    #[test]
    fn rreq_hop_limit_above_max_rejected() {
        for hop in [MAX_HOP_LIMIT + 1, u8::MAX] {
            let mut wire = [0u8; RREQ_RREP_LEN];
            wire[1] = hop;
            wire[2..4].copy_from_slice(&1u16.to_be_bytes());
            wire[4..20].copy_from_slice(&ll(1).0);
            wire[20..36].copy_from_slice(&ll(2).0);
            assert_eq!(
                Rreq::from_bytes(&wire),
                Err(LoadngError::HopLimitExceeded { got: hop })
            );
        }
    }

    #[test]
    fn rreq_hop_limit_boundaries_accepted() {
        // Canonical vectors rreq_zero_hop_limit / rreq_max_hop_limit bound
        // the accepted range at both ends.
        for hop in [0u8, INITIAL_HOP_LIMIT, MAX_HOP_LIMIT] {
            let rreq = Rreq {
                originator: ll(1),
                destination: ll(2),
                seq_num: 100,
                hop_limit: hop,
                flags: 0,
            };
            let mut buf = [0u8; 64];
            let n = rreq.write_to(&mut buf).unwrap();
            let parsed = Rreq::from_bytes(&buf[..n]).unwrap();
            assert_eq!(parsed.hop_limit, hop);
        }
    }

    #[test]
    fn rrep_hop_count_above_max_rejected() {
        for count in [MAX_HOP_LIMIT + 1, u8::MAX] {
            let mut wire = [0u8; RREQ_RREP_LEN];
            wire[1] = count;
            wire[2..4].copy_from_slice(&50u16.to_be_bytes());
            wire[4..20].copy_from_slice(&ll(1).0);
            wire[20..36].copy_from_slice(&ll(2).0);
            assert_eq!(
                Rrep::from_bytes(&wire),
                Err(LoadngError::HopLimitExceeded { got: count })
            );
        }
    }

    #[test]
    fn rrep_hop_count_boundaries_accepted() {
        // Canonical vectors rrep_zero_hop_count / rrep_max_hop_count.
        let max_count: [u8; 36] =
            hex("000f00320200112233445566001122334455660102001122334455660011223344556602");
        let parsed = Rrep::from_bytes(&max_count).unwrap();
        assert_eq!(parsed.hop_count, MAX_HOP_LIMIT);
        assert_eq!(parsed.seq_num, 50);

        let zero_count: [u8; 36] =
            hex("000000010200112233445566001122334455660102001122334455660011223344556602");
        let parsed = Rrep::from_bytes(&zero_count).unwrap();
        assert_eq!(parsed.hop_count, 0);
        assert_eq!(parsed.seq_num, 1);
    }

    /// Decode an even-length lowercase hex string literal into exactly
    /// N bytes. Test-only helper; panics on malformed input.
    fn hex<const N: usize>(s: &str) -> [u8; N] {
        let bytes = s.as_bytes();
        assert_eq!(bytes.len(), N * 2);
        let nibble = |b: u8| match b {
            b'0'..=b'9' => b - b'0',
            b'a'..=b'f' => b - b'a' + 10,
            _ => panic!("bad hex digit"),
        };
        let mut out = [0u8; N];
        let mut i = 0;
        while i < N {
            out[i] = (nibble(bytes[2 * i]) << 4) | nibble(bytes[2 * i + 1]);
            i += 1;
        }
        out
    }

    #[test]
    fn loadng_message_dispatch() {
        let rreq = Rreq {
            originator: ll(1),
            destination: ll(2),
            seq_num: 100,
            hop_limit: 4,
            flags: 0,
        };
        let mut buf = [0u8; 64];
        rreq.write_to(&mut buf).unwrap();

        let msg = LoadngMessage::from_icmpv6(0, &buf).unwrap();
        assert!(matches!(msg, LoadngMessage::Rreq(_)));
        assert_eq!(msg.code(), 0);
    }

    #[test]
    fn hop_limit_decrement() {
        let rreq = Rreq {
            originator: ll(1),
            destination: ll(2),
            seq_num: 1,
            hop_limit: 2,
            flags: 0,
        };
        let dec = rreq.with_decremented_hop_limit().unwrap();
        assert_eq!(dec.hop_limit, 1);

        let dec2 = dec.with_decremented_hop_limit().unwrap();
        assert_eq!(dec2.hop_limit, 0);

        assert!(dec2.with_decremented_hop_limit().is_none());
    }

    #[test]
    fn route_discovery_expanding_ring_typestate() {
        let idle = RouteDiscovery::<Idle>::new(ll(1), ll(2), 0x2222);
        assert_eq!(idle.state(), RouteDiscoveryState::Idle);

        let (searching, rreq) = idle.start();
        assert_eq!(searching.state(), RouteDiscoveryState::Searching);
        assert_eq!(rreq.originator, ll(1));
        assert_eq!(rreq.destination, ll(2));
        assert_eq!(rreq.seq_num, 0x2222);
        assert_eq!(rreq.hop_limit, EXPANDING_RING[0]);

        let (searching, rreq) = searching.advance_ring().unwrap();
        assert_eq!(searching.ring_index(), 1);
        assert_eq!(rreq.hop_limit, EXPANDING_RING[1]);

        let (searching, rreq) = searching.advance_ring().unwrap();
        assert_eq!(searching.ring_index(), 2);
        assert_eq!(rreq.hop_limit, EXPANDING_RING[2]);

        let failed = searching.advance_ring().unwrap_err();
        assert_eq!(failed.state(), RouteDiscoveryState::Failed);
    }

    #[test]
    fn route_discovery_accepts_matching_rrep() {
        let (searching, _) = RouteDiscovery::<Idle>::new(ll(1), ll(2), 0x3333).start();
        let replied = searching
            .receive_rrep(Rrep {
                originator: ll(2),
                destination: ll(1),
                seq_num: 0x3333,
                hop_count: 2,
                flags: 0,
            })
            .unwrap();
        assert_eq!(replied.state(), RouteDiscoveryState::Replied);
        assert_eq!(replied.originator(), ll(1));
        assert_eq!(replied.destination(), ll(2));
    }

    #[test]
    fn route_discovery_rejects_wrong_rrep() {
        let (searching, _) = RouteDiscovery::<Idle>::new(ll(1), ll(2), 0x3333).start();
        let err = searching
            .receive_rrep(Rrep {
                originator: ll(3),
                destination: ll(1),
                seq_num: 0x3333,
                hop_count: 2,
                flags: 0,
            })
            .unwrap_err();
        assert_eq!(err, LoadngError::InvalidDiscoveryReply);
    }

    fn ll_seq_is_fresher(old_seq: u16, new_seq: u16) -> bool {
        seq_is_fresher(old_seq, new_seq)
    }

    #[test]
    fn seq_freshness_equal() {
        assert!(!ll_seq_is_fresher(0, 0));
    }

    #[test]
    fn seq_freshness_simple_increment() {
        assert!(ll_seq_is_fresher(0, 1));
    }

    #[test]
    fn seq_freshness_simple_decrement() {
        assert!(!ll_seq_is_fresher(1, 0));
    }

    #[test]
    fn seq_freshness_forward_100() {
        assert!(ll_seq_is_fresher(0, 100));
    }

    #[test]
    fn seq_freshness_backward_100() {
        assert!(!ll_seq_is_fresher(100, 0));
    }

    #[test]
    fn seq_freshness_half_range_boundary_not_fresher() {
        assert!(!ll_seq_is_fresher(0, 0x8000));
    }

    #[test]
    fn seq_freshness_half_range_just_below_fresher() {
        assert!(ll_seq_is_fresher(0, 0x7FFF));
    }

    #[test]
    #[allow(non_snake_case)]
    fn seq_freshness_wrap_forward_FFFF_to_0000() {
        assert!(ll_seq_is_fresher(0xFFFF, 0));
    }

    #[test]
    #[allow(non_snake_case)]
    fn seq_freshness_wrap_forward_FFFF_to_0001() {
        assert!(ll_seq_is_fresher(0xFFFF, 1));
    }

    #[test]
    #[allow(non_snake_case)]
    fn seq_freshness_wrap_backward_0000_to_FFFF() {
        assert!(!ll_seq_is_fresher(0, 0xFFFF));
    }

    #[test]
    fn seq_freshness_wrap_forward_65530_to_5() {
        assert!(ll_seq_is_fresher(65530, 5));
    }

    #[test]
    fn seq_freshness_wrap_backward_5_to_65530() {
        assert!(!ll_seq_is_fresher(5, 65530));
    }

    #[test]
    fn seq_freshness_half_to_zero() {
        assert!(!ll_seq_is_fresher(0x8000, 0));
    }

    #[test]
    fn seq_freshness_half_minus_one_to_zero() {
        assert!(ll_seq_is_fresher(0x8001, 0));
    }

    #[test]
    fn seq_freshness_near_half_forward() {
        assert!(ll_seq_is_fresher(0x7FFF, 0x8000));
    }

    #[test]
    fn seq_freshness_max_range_minus_one() {
        assert!(!ll_seq_is_fresher(0, 0xFFFE));
    }

    #[test]
    fn route_discovery_runtime_transition_table_rejects_invalid_edges() {
        assert!(RouteDiscoveryState::Idle
            .transition_to(RouteDiscoveryState::Searching)
            .is_ok());
        assert_eq!(
            RouteDiscoveryState::Idle.transition_to(RouteDiscoveryState::Replied),
            Err(LoadngError::InvalidDiscoveryTransition {
                from: RouteDiscoveryState::Idle,
                to: RouteDiscoveryState::Replied,
            })
        );
        assert_eq!(
            RouteDiscoveryState::Failed.transition_to(RouteDiscoveryState::Searching),
            Err(LoadngError::InvalidDiscoveryTransition {
                from: RouteDiscoveryState::Failed,
                to: RouteDiscoveryState::Searching,
            })
        );
    }

    #[test]
    fn rrep_is_proxy_flag() {
        // Authoritative reply (from actual destination): flags=0
        let authoritative = Rrep {
            originator: ll(2),
            destination: ll(1),
            seq_num: 100,
            hop_count: 2,
            flags: 0,
        };
        assert!(!authoritative.is_proxy());

        // Proxy/intermediate reply (from cached gradient): flags=0x01
        let proxy = Rrep {
            originator: ll(2),
            destination: ll(1),
            seq_num: 100,
            hop_count: 2,
            flags: RREP_FLAG_PROXY,
        };
        assert!(proxy.is_proxy());

        // Proxy flag with other bits set
        let mixed_flags = Rrep {
            originator: ll(2),
            destination: ll(1),
            seq_num: 100,
            hop_count: 2,
            flags: 0x81, // bit 0 and bit 7 set
        };
        assert!(mixed_flags.is_proxy());
    }
}
