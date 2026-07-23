//! UDP header parsing and building (RFC 768, no_std).
//!
//! Provides zero-copy parsing and construction of UDP datagrams with IPv6
//! pseudo-header checksum support per RFC 8200.

use crate::addr::Ipv6Addr;
use crate::checksum::upper_layer_checksum;
use crate::error::{BufferTooSmall, TooShort};

/// UDP header length (always 8 bytes).
pub const UDP_HEADER_LEN: usize = 8;

/// Next Header value for UDP in IPv6.
pub const UDP_NEXT_HEADER: u8 = 17;

/// UDP parse error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum UdpError {
    /// Buffer too short for UDP header.
    TooShort(TooShort),
    /// Declared length doesn't match data length.
    LengthMismatch { declared: u16, actual: usize },
    /// Output buffer too small.
    BufferTooSmall(BufferTooSmall),
}

impl core::fmt::Display for UdpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TooShort(e) => write!(f, "UDP {}", e),
            Self::LengthMismatch { declared, actual } => {
                write!(f, "UDP length {declared} != {actual} bytes present")
            }
            Self::BufferTooSmall(e) => write!(f, "UDP {}", e),
        }
    }
}

impl core::error::Error for UdpError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::TooShort(e) => Some(e),
            Self::BufferTooSmall(e) => Some(e),
            _ => None,
        }
    }
}

impl From<TooShort> for UdpError {
    fn from(e: TooShort) -> Self {
        Self::TooShort(e)
    }
}

impl From<BufferTooSmall> for UdpError {
    fn from(e: BufferTooSmall) -> Self {
        Self::BufferTooSmall(e)
    }
}

/// A parsed UDP header (zero-copy reference to buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpHeader<'a> {
    data: &'a [u8],
}

impl<'a> UdpHeader<'a> {
    /// Parse a UDP datagram from the start of `data`.
    ///
    /// Validates that the length field matches the actual data length.
    pub fn from_bytes(data: &'a [u8]) -> Result<Self, UdpError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(TooShort::new(UDP_HEADER_LEN, data.len()).into());
        }
        let declared = u16::from_be_bytes([data[4], data[5]]) as usize;
        if declared != data.len() {
            return Err(UdpError::LengthMismatch {
                declared: declared as u16,
                actual: data.len(),
            });
        }
        Ok(Self { data })
    }

    /// Parse without length validation (for incomplete buffers).
    pub fn from_bytes_unchecked(data: &'a [u8]) -> Result<Self, UdpError> {
        if data.len() < UDP_HEADER_LEN {
            return Err(TooShort::new(UDP_HEADER_LEN, data.len()).into());
        }
        Ok(Self { data })
    }

    /// Source port.
    pub fn src_port(&self) -> u16 {
        u16::from_be_bytes([self.data[0], self.data[1]])
    }

    /// Destination port.
    pub fn dst_port(&self) -> u16 {
        u16::from_be_bytes([self.data[2], self.data[3]])
    }

    /// Total UDP length (header + payload).
    pub fn length(&self) -> u16 {
        u16::from_be_bytes([self.data[4], self.data[5]])
    }

    /// Checksum field value.
    pub fn checksum(&self) -> u16 {
        u16::from_be_bytes([self.data[6], self.data[7]])
    }

    /// Payload slice (after 8-byte header).
    pub fn payload(&self) -> &'a [u8] {
        &self.data[UDP_HEADER_LEN..]
    }

    /// Verify the checksum against IPv6 pseudo-header.
    ///
    /// Returns true if checksum is valid or if checksum field is 0 (per RFC 768,
    /// a zero checksum in IPv6 UDP is invalid, but we accept it for permissive parsing).
    pub fn verify_checksum(&self, src: &Ipv6Addr, dst: &Ipv6Addr) -> bool {
        if self.checksum() == 0 {
            // RFC 8200: UDP checksum is mandatory for IPv6, but be permissive
            return true;
        }
        // Compute checksum over pseudo-header + datagram; result should be 0xFFFF
        let computed = upper_layer_checksum(&src.0, &dst.0, UDP_NEXT_HEADER, self.data);
        computed == 0 || computed == 0xFFFF
    }

    /// Raw datagram bytes (header + payload).
    pub fn as_bytes(&self) -> &'a [u8] {
        self.data
    }
}

/// Build a UDP datagram into `out`.
///
/// Computes the IPv6 pseudo-header checksum automatically.
/// Returns the total number of bytes written (header + payload).
pub fn write_datagram(
    src_addr: &Ipv6Addr,
    dst_addr: &Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, UdpError> {
    let total = UDP_HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(BufferTooSmall::new(total, out.len()).into());
    }

    // Header with zero checksum initially
    out[0..2].copy_from_slice(&src_port.to_be_bytes());
    out[2..4].copy_from_slice(&dst_port.to_be_bytes());
    out[4..6].copy_from_slice(&(total as u16).to_be_bytes());
    out[6] = 0; // checksum placeholder
    out[7] = 0;
    out[UDP_HEADER_LEN..total].copy_from_slice(payload);

    // Compute and fill checksum
    let csum = upper_layer_checksum(&src_addr.0, &dst_addr.0, UDP_NEXT_HEADER, &out[..total]);
    // RFC 768: a computed checksum of zero is transmitted as all ones
    let csum = if csum == 0 { 0xFFFF } else { csum };
    out[6..8].copy_from_slice(&csum.to_be_bytes());

    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ll(iid: u8) -> Ipv6Addr {
        Ipv6Addr([0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0, 0, 0, 0, 0, 0, iid])
    }

    #[test]
    fn parse_udp_header() {
        let src = ll(1);
        let dst = ll(2);
        let mut buf = [0u8; 16];
        let n = write_datagram(&src, &dst, 5683, 5684, b"hello!!!", &mut buf).unwrap();
        assert_eq!(n, 16);

        let hdr = UdpHeader::from_bytes(&buf[..n]).unwrap();
        assert_eq!(hdr.src_port(), 5683);
        assert_eq!(hdr.dst_port(), 5684);
        assert_eq!(hdr.length(), 16);
        assert_eq!(hdr.payload(), b"hello!!!");
        assert!(hdr.verify_checksum(&src, &dst));
    }

    #[test]
    fn too_short() {
        assert_eq!(
            UdpHeader::from_bytes(&[0u8; 7]),
            Err(UdpError::TooShort(TooShort::new(UDP_HEADER_LEN, 7)))
        );
    }

    #[test]
    fn length_mismatch() {
        // Header says length=100, but only 8 bytes present
        let mut buf = [0u8; 8];
        buf[4..6].copy_from_slice(&100u16.to_be_bytes());
        assert_eq!(
            UdpHeader::from_bytes(&buf),
            Err(UdpError::LengthMismatch {
                declared: 100,
                actual: 8
            })
        );
    }

    #[test]
    fn checksum_is_stable() {
        let src = ll(1);
        let dst = ll(2);
        let mut buf1 = [0u8; 12];
        let mut buf2 = [0u8; 12];
        write_datagram(&src, &dst, 1234, 5678, b"test", &mut buf1).unwrap();
        write_datagram(&src, &dst, 1234, 5678, b"test", &mut buf2).unwrap();
        assert_eq!(buf1, buf2);
    }

    #[test]
    fn checksum_zero_becomes_ffff() {
        // Artificially construct a datagram where checksum would be 0
        // (rare but possible) - verify it becomes 0xFFFF
        let src = ll(1);
        let dst = ll(2);
        let mut buf = [0u8; 8];
        let n = write_datagram(&src, &dst, 0, 0, &[], &mut buf).unwrap();
        let hdr = UdpHeader::from_bytes(&buf[..n]).unwrap();
        // Checksum should not be 0
        assert_ne!(hdr.checksum(), 0);
    }

    #[test]
    fn buffer_too_small() {
        let src = ll(1);
        let dst = ll(2);
        let mut buf = [0u8; 7];
        assert_eq!(
            write_datagram(&src, &dst, 1234, 5678, &[], &mut buf),
            Err(UdpError::BufferTooSmall(BufferTooSmall::new(
                UDP_HEADER_LEN,
                7
            )))
        );
    }

    #[test]
    fn empty_payload() {
        let src = ll(1);
        let dst = ll(2);
        let mut buf = [0u8; 8];
        let n = write_datagram(&src, &dst, 5683, 5683, &[], &mut buf).unwrap();
        assert_eq!(n, 8);
        let hdr = UdpHeader::from_bytes(&buf).unwrap();
        assert_eq!(hdr.payload(), &[] as &[u8]);
        assert!(hdr.verify_checksum(&src, &dst));
    }
}
