//! Hop-by-hop relay: verify, mutate, re-sign (spec/06-security.md §8.4).
//!
//! The link signature is hop-by-hop and covers the current link destination
//! and payload. A forwarding node MUST verify the inbound signature against
//! the pinned peer key (advancing that peer's replay window) BEFORE applying
//! any mutation, then create a NEW frame for the next hop carrying its own
//! signer identity, its own replay counter, and a fresh Schnorr48 signature
//! over the complete new frame. Hop Limit changes, RFC 6554 address swaps,
//! source-routing-header updates, and link-address changes therefore never
//! occur under an unchanged link signature.

use crate::frame::{AddrMode, FrameError};
use crate::identity::PeerIdentity;
use crate::link_layer::{LinkLayer, LinkRxError};
use crate::seqnum::LinkSeqNum;

/// Failure of a hop-by-hop relay attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RelayError {
    /// Inbound authentication failed. Nothing was mutated or emitted; the
    /// caller's output buffer is left untouched.
    Inbound(LinkRxError),
    /// Outbound framing failed after successful inbound verification.
    Outbound(FrameError),
}

impl core::fmt::Display for RelayError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Inbound(e) => write!(f, "inbound verification failed: {}", e),
            Self::Outbound(e) => write!(f, "outbound framing failed: {}", e),
        }
    }
}

impl core::error::Error for RelayError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Inbound(e) => Some(e),
            Self::Outbound(e) => Some(e),
        }
    }
}

/// Successful hop-by-hop relay result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayOutcome {
    /// Wire bytes written to the caller's output buffer.
    pub len: usize,
    /// Identity whose signature authenticated the inbound frame. Routing
    /// layers that preserve origin provenance (e.g. the DAO Origin Signature)
    /// derive it from this verified upstream, never from wire bytes.
    pub upstream: PeerIdentity,
}

impl LinkLayer {
    /// Verify an inbound signed frame, apply the caller's permitted mutation,
    /// and emit a freshly signed frame for the next hop (spec 8.4).
    ///
    /// The order of operations is normative:
    ///
    /// 1. **Verify** — the full receive pipeline runs against the pinned peer
    ///    key: structural parsing, signer-EUI-64 lookup, Schnorr48
    ///    verification over the exact wire transcript, key-pin check, and
    ///    replay-window update for the authenticated sender. Any failure
    ///    returns [`RelayError::Inbound`] before any mutation or emission;
    ///    `out` is untouched.
    /// 2. **Mutate** — the outbound payload is `payload_override` when the
    ///    relay applies a permitted mutation (Hop Limit decrement,
    ///    source-routing-header update, ...), otherwise the verified inbound
    ///    payload verbatim.
    /// 3. **Re-sign** — [`LinkLayer::build_frame_with_addr_mode`] creates a
    ///    new frame toward `next_dst` signed with THIS node's own key and
    ///    bearing its own canonical signer EUI-64 and its own replay counter
    ///    (`epoch`, `seqnum`). The inbound MIC is never forwarded.
    ///
    /// Callers MUST derive `payload_override` from the verified inbound
    /// payload of an earlier authenticated receive (or from this call's own
    /// verified frame via [`AuthenticatedFrame`](crate::link_layer::AuthenticatedFrame));
    /// mutating bytes from an unverified source defeats the verify step.
    #[allow(clippy::too_many_arguments)]
    pub fn relay_verified_frame(
        &mut self,
        inbound_wire: &[u8],
        next_dst: &[u8],
        next_addr_mode: AddrMode,
        payload_override: Option<&[u8]>,
        epoch: u8,
        seqnum: LinkSeqNum,
        out: &mut [u8],
    ) -> Result<RelayOutcome, RelayError> {
        let verified = self
            .receive_frame(inbound_wire)
            .map_err(RelayError::Inbound)?;
        let upstream = verified.sender().clone();
        let outbound_payload = match payload_override {
            Some(mutated) => mutated,
            None => verified.payload(),
        };
        let len = self
            .build_frame_with_addr_mode(
                epoch,
                seqnum,
                next_dst,
                outbound_payload,
                next_addr_mode,
                out,
            )
            .map_err(RelayError::Outbound)?;
        Ok(RelayOutcome { len, upstream })
    }
}
