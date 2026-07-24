//! Async UDP CoAP client (requires `tokio` feature).
//!
//! Sends a single CoAP request and waits for a response, with a 5-second
//! timeout.  Supports GET, POST, and PUT with optional CBOR payloads.
//!
//! This is intentionally minimal — no retransmission logic, no Observe, no
//! block-wise transfer.  It is suitable for CLI and TUI tools that talk to a
//! local LICHEN node over the loopback or LAN.

use std::collections::hash_map::RandomState;
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

use crate::codec::{CoapBuilder, CoapPacket};
use crate::message::{MessageCode, MessageType};
use crate::option::content_format;

const TIMEOUT_S: u64 = 5;
static REQUEST_SEQUENCE: OnceLock<AtomicU64> = OnceLock::new();

/// A decoded CoAP response.
#[derive(Debug)]
pub struct Response {
    /// Raw CoAP code byte (class in upper 3 bits, detail in lower 5).
    pub code: u8,
    /// Response payload (empty if none).
    pub payload: Vec<u8>,
}

impl Response {
    /// True for 2.xx success codes.
    pub fn is_success(&self) -> bool {
        self.code >> 5 == 2
    }

    /// Human-readable code string, e.g. `"2.05"`.
    pub fn code_str(&self) -> String {
        format!("{}.{:02}", self.code >> 5, self.code & 0x1f)
    }
}

/// GET coap://\[addr\]\[path\].
pub async fn get(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    request(addr, MessageCode::GET, path, None).await
}

/// POST coap://\[addr\]\[path\] with CBOR body.
pub async fn post(addr: SocketAddr, path: &str, body: &[u8]) -> std::io::Result<Response> {
    request(addr, MessageCode::POST, path, Some(body)).await
}

/// PUT coap://\[addr\]\[path\] with CBOR body.
pub async fn put(addr: SocketAddr, path: &str, body: &[u8]) -> std::io::Result<Response> {
    request(addr, MessageCode::PUT, path, Some(body)).await
}

/// DELETE coap://\[addr\]\[path\].
pub async fn delete(addr: SocketAddr, path: &str) -> std::io::Result<Response> {
    request(addr, MessageCode::DELETE, path, None).await
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

async fn request(
    addr: SocketAddr,
    code: MessageCode,
    path: &str,
    payload: Option<&[u8]>,
) -> std::io::Result<Response> {
    let bind = if addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let sock = UdpSocket::bind(bind).await?;
    sock.connect(addr).await?;

    let (mid, token) = next_request_id(request_sequence())?;
    let frame = encode(code, mid, &token, path, payload)?;

    sock.send(&frame).await?;

    let mut buf = vec![0u8; 1280];
    let n = timeout(Duration::from_secs(TIMEOUT_S), sock.recv(&mut buf))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "CoAP timeout"))??;

    // SECURITY: Validate response MID and token match request (RFC 7252 Sections 4.4 and 5.3.1)
    decode(&buf[..n], mid, &token)
}

/// Build a CoAP message using CoapBuilder.
fn encode(
    code: MessageCode,
    mid: u16,
    token: &[u8],
    path: &str,
    payload: Option<&[u8]>,
) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; 256];

    let mut builder = CoapBuilder::new(&mut buf, MessageType::Confirmable, code, mid, token)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string()))?;

    // Add Uri-Path options for each path segment
    for seg in path.trim_start_matches('/').split('/') {
        if !seg.is_empty() {
            builder.uri_path(seg).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
        }
    }

    // Add Content-Format (CBOR) and payload when body is present (RFC 7252 §12.3)
    if let Some(p) = payload {
        if !p.is_empty() {
            builder.content_format(content_format::CBOR).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
            builder.payload(p).map_err(|e| {
                std::io::Error::new(std::io::ErrorKind::InvalidInput, e.to_string())
            })?;
        }
    }

    let len = builder.finish();
    buf.truncate(len);
    Ok(buf)
}

/// Parse a CoAP response using canonical codec (eliminates duplicated parser).
/// SECURITY: Validates MID + token match per RFC 7252 §§4.4, 5.3.1. Uses
/// CoapPacket::from_bytes for version/TKL/option validation + payload offset.
fn decode(data: &[u8], expected_mid: u16, expected_token: &[u8]) -> std::io::Result<Response> {
    let packet = CoapPacket::from_bytes(data).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("CoAP parse error: {}", e),
        )
    })?;

    if packet.message_id() != expected_mid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response MID does not match request MID",
        ));
    }

    if packet.token() != expected_token {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "response token does not match request token",
        ));
    }

    Ok(Response {
        code: packet.code().0,
        payload: packet.payload().to_vec(),
    })
}

fn next_request_id(sequence: &AtomicU64) -> std::io::Result<(u16, [u8; 8])> {
    let value = sequence
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
            value.checked_add(1)
        })
        .map_err(|_| std::io::Error::other("CoAP request ID space exhausted"))?;
    Ok((value as u16, value.to_be_bytes()))
}

fn request_sequence() -> &'static AtomicU64 {
    REQUEST_SEQUENCE.get_or_init(|| {
        let seed = RandomState::new().hash_one("LICHEN CoAP request sequence");
        AtomicU64::new(seed)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{ACK_HEADER, PAYLOAD_MARKER};
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use std::thread;

    /// Build a minimal CoAP response: Ver=1, Type=ACK, TKL, Code, MID, Token, optional payload (RFC 7252).
    fn build_response(code: MessageCode, mid: u16, token: &[u8], payload: Option<&[u8]>) -> Vec<u8> {
        let tkl = token.len() as u8;
        assert!(tkl <= 8, "token too long");
        // Ver=1 (bits 7-6), Type=ACK=2 (bits 5-4), TKL (bits 3-0)
        let byte0 = ACK_HEADER | tkl;
        let mid_bytes = mid.to_be_bytes();
        let mut data = vec![byte0, code.0, mid_bytes[0], mid_bytes[1]];
        data.extend_from_slice(token);
        if let Some(p) = payload {
            if !p.is_empty() {
                data.push(PAYLOAD_MARKER);
                data.extend_from_slice(p);
            }
        }
        data
    }

    #[test]
    fn decode_accepts_matching_mid_and_token() {
        let sequence = AtomicU64::new(0x1234);
        let (mid, token) = next_request_id(&sequence).unwrap();
        let resp_data = build_response(MessageCode::CONTENT, mid, &token, Some(b"hello")); // 2.05 Content (RFC 7252)
        let result = decode(&resp_data, mid, &token);
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.code, MessageCode::CONTENT.0);
        assert_eq!(resp.payload, b"hello");
    }

    #[test]
    fn decode_rejects_mismatched_mid() {
        let request_mid = 0x1234;
        let attacker_mid = 0xDEAD;
        let token = [0x4c, 0x49, 0x43, 0x48]; // "LICH"
                                              // Attacker knows token but guesses wrong MID
        let spoofed_resp = build_response(MessageCode::CONTENT, attacker_mid, &token, Some(b"fake"));
        let result = decode(&spoofed_resp, request_mid, &token);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("MID"));
    }

    #[test]
    fn decode_rejects_mismatched_token() {
        let mid = 0x1234;
        let request_token = [0x4c, 0x49, 0x43, 0x48]; // "LICH"
        let attacker_token = [0x45, 0x56, 0x49, 0x4c]; // "EVIL"
        let spoofed_resp = build_response(MessageCode::CONTENT, mid, &attacker_token, Some(b"fake"));
        let result = decode(&spoofed_resp, mid, &request_token);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("token"));
    }

    #[test]
    fn decode_rejects_wrong_length_token() {
        let mid = 0x1234;
        let request_token = [0x4c, 0x49, 0x43, 0x48]; // 4 bytes
        let short_token = [0x4c, 0x49]; // 2 bytes
        let spoofed_resp = build_response(MessageCode::CONTENT, mid, &short_token, None);
        let result = decode(&spoofed_resp, mid, &request_token);
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn decode_accepts_empty_token_when_expected() {
        let mid = 0x5678;
        let empty_token: [u8; 0] = [];
        let resp_data = build_response(MessageCode::CONTENT, mid, &empty_token, Some(b"data"));
        let result = decode(&resp_data, mid, &empty_token);
        assert!(result.is_ok());
        let resp = result.unwrap();
        assert_eq!(resp.payload, b"data");
    }

    #[test]
    fn decode_rejects_nonempty_when_empty_expected() {
        let mid = 0xABCD;
        let empty_token: [u8; 0] = [];
        let nonempty_token = [0x41, 0x42];
        let resp_data = build_response(MessageCode::CONTENT, mid, &nonempty_token, None);
        let result = decode(&resp_data, mid, &empty_token);
        assert!(result.is_err());
    }

    #[test]
    fn decode_rejects_both_wrong_mid_and_token() {
        // Even if attacker guesses one correctly, must match both
        let request_mid = 0x1234;
        let request_token = [0x4c, 0x49, 0x43, 0x48]; // "LICH"
        let attacker_mid = 0xBEEF;
        let attacker_token = [0x45, 0x56, 0x49, 0x4c]; // "EVIL"
        let spoofed_resp = build_response(MessageCode::CONTENT, attacker_mid, &attacker_token, Some(b"pwned"));
        let result = decode(&spoofed_resp, request_mid, &request_token);
        assert!(result.is_err());
        // Should fail on MID check first
        let err = result.unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::InvalidData);
    }

    #[test]
    fn request_ids_are_unique_concurrently() {
        let sequence = Arc::new(AtomicU64::new(0));
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let sequence = Arc::clone(&sequence);
                thread::spawn(move || {
                    (0..1000)
                        .map(|_| next_request_id(&sequence).unwrap())
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        let mut seen = HashSet::new();

        for thread in threads {
            for id in thread.join().unwrap() {
                assert!(seen.insert(id));
            }
        }
        assert_eq!(seen.len(), 8000);
    }

    #[test]
    fn request_ids_remain_unique_across_mid_rollover() {
        let sequence = AtomicU64::new(u16::MAX as u64);
        let first = next_request_id(&sequence).unwrap();
        let second = next_request_id(&sequence).unwrap();

        assert_eq!(first.0, u16::MAX);
        assert_eq!(second.0, 0);
        assert_ne!(first.1, second.1);
        assert_ne!(first, second);
    }

    #[test]
    fn request_id_exhaustion_does_not_wrap() {
        let sequence = AtomicU64::new(u64::MAX - 1);
        let last = next_request_id(&sequence).unwrap();

        assert_eq!(last.1, (u64::MAX - 1).to_be_bytes());
        assert!(next_request_id(&sequence).is_err());
        assert!(next_request_id(&sequence).is_err());
        assert_eq!(sequence.load(Ordering::Relaxed), u64::MAX);
    }
}
