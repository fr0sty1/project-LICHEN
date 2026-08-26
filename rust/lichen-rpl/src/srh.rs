//! Source Routing Header (RFC 6554).
//!
//! RFC 6554 SRH wire format encoding and decoding.

#[cfg(feature = "std")]
use std::vec::Vec;

#[cfg(feature = "std")]
use crate::message::RplError;
#[cfg(feature = "std")]
use lichen_core::error::{BufferTooSmall, TooShort};

/// Maximum complete route hops allowed by the LICHEN RPL profile.
pub const MAX_ROUTE_HOPS: usize = 8;

/// RFC 6554 Source Routing Header, routing type 3 (uncompressed).
///
/// `addresses` are the hops still to visit; `segments_left` counts how many remain.
#[cfg(feature = "std")]
#[derive(Debug, PartialEq, Eq)]
pub struct SourceRoutingHeader {
    pub segments_left: u8,
    pub addresses: Vec<[u8; 16]>,
}

#[cfg(feature = "std")]
impl SourceRoutingHeader {
    /// Encode to the SRH wire format: 6 fixed bytes + 16 bytes per address.
    pub fn write_to(&self, out: &mut [u8]) -> Result<usize, RplError> {
        if self.addresses.len() > MAX_ROUTE_HOPS
            || usize::from(self.segments_left) > self.addresses.len()
        {
            return Err(RplError::InvalidOption);
        }
        let needed = 6 + self.addresses.len() * 16;
        if out.len() < needed {
            return Err(BufferTooSmall::new(needed, out.len()).into());
        }
        out[0] = 3; // routing type
        out[1] = self.segments_left;
        out[2] = 0; // CmprI
        out[3] = 0; // CmprE
        out[4] = 0; // reserved
        out[5] = 0;
        for (i, addr) in self.addresses.iter().enumerate() {
            out[6 + i * 16..6 + (i + 1) * 16].copy_from_slice(addr);
        }
        Ok(needed)
    }

    /// Parse from SRH wire bytes (starting at the routing-type byte).
    pub fn from_bytes(data: &[u8]) -> Result<Self, RplError> {
        if data.len() < 6 {
            return Err(TooShort::new(6, data.len()).into());
        }
        if data[0] != 3 {
            return Err(RplError::BadRoutingType(data[0]));
        }
        // SECURITY: Reject compressed or padded SRHs. We only support full
        // 16-byte addresses, so accepting either would change the address
        // boundaries below. RFC 6554 requires receivers to ignore the low
        // reserved nibble of data[3] and the reserved bytes data[4..6].
        if data[2] != 0 || data[3] & 0xf0 != 0 {
            return Err(RplError::InvalidOption);
        }
        let addr_bytes = &data[6..];
        if !addr_bytes.len().is_multiple_of(16) {
            return Err(RplError::InvalidOption);
        }
        let addresses: Vec<[u8; 16]> = addr_bytes
            .chunks_exact(16)
            .map(|chunk| chunk.try_into().unwrap())
            .collect();
        if addresses.len() > MAX_ROUTE_HOPS {
            return Err(RplError::InvalidOption);
        }
        let segments_left = data[1];
        if (segments_left as usize) > addresses.len() {
            return Err(RplError::InvalidOption);
        }
        Ok(Self {
            segments_left,
            addresses,
        })
    }

    pub fn from_route(route: &[[u8; 16]]) -> Result<Self, RplError> {
        let remaining = route.len().checked_sub(1).ok_or(RplError::InvalidOption)?;
        if remaining == 0 || route.len() > MAX_ROUTE_HOPS {
            return Err(RplError::InvalidOption);
        }
        let addresses = route[1..].to_vec();
        Ok(Self {
            segments_left: remaining as u8,
            addresses,
        })
    }

    /// Validate segments_left < hop_limit per RFC 6554 + LICHEN spec §5 line 418.
    ///
    /// Returns `true` if valid (segments_left strictly less than hop_limit),
    /// `false` if the packet cannot complete the source route before TTL expiry.
    pub fn validate_hop_limit(&self, hop_limit: u8) -> bool {
        self.segments_left < hop_limit
    }
}
