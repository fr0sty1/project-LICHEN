//! Async UDP CoAP client (requires `tokio` feature).
//!
//! Sends a single CoAP request and waits for a response, with a 5-second
//! timeout.  Supports GET, POST, and PUT with optional CBOR payloads.
//!
//! This is intentionally minimal — no retransmission logic, no Observe, no
//! block-wise transfer.  It is suitable for CLI and TUI tools that talk to a
//! local LICHEN node over the loopback or LAN.
//!
//! # 5.03 Service Unavailable Backoff (spec 07 section 10.2.3)
//!
//! Per spec: "Senders receiving 5.03 MUST back off for the indicated duration."
//! The [`CoapClient`] struct tracks peer backoff state and refuses new requests
//! to peers that are in backoff. The standalone functions ([`get`], [`post`], etc.)
//! do NOT track backoff state across calls.

use std::collections::hash_map::RandomState;
use std::collections::HashMap;
use std::hash::BuildHasher;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicU64, Ordering},
    OnceLock,
};
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration, Instant};

use crate::codec::{CoapBuilder, CoapPacket};
use crate::message::{MessageCode, MessageType};
use crate::option::{content_format, OptionNumber};

const TIMEOUT_S: u64 = 5;

/// Default backoff when 5.03 has no Max-Age option (spec 07 section 10.2.3).
const DEFAULT_503_BACKOFF_S: u64 = 60;

/// SECURITY: Cap backoff to 1 hour to prevent DoS from malicious Max-Age values.
/// The spec's rolling 1-hour duty cycle window means no legitimate congestion
/// recovery can exceed 3600 seconds.
const MAX_BACKOFF_S: u64 = 3600;
static REQUEST_SEQUENCE: OnceLock<AtomicU64> = OnceLock::new();

/// A decoded CoAP response.
#[derive(Debug)]
pub struct Response {
    /// Raw CoAP code byte (class in upper 3 bits, detail in lower 5).
    pub code: u8,
    /// Response payload (empty if none).
    pub payload: Vec<u8>,
    /// Max-Age option value in seconds, if present.
    pub max_age: Option<u32>,
}

impl Response {
    /// True for 2.xx success codes.
    pub fn is_success(&self) -> bool {
        self.code >> 5 == 2
    }

    /// True for 5.03 Service Unavailable (spec 07 section 10.2.3).
    pub fn is_service_unavailable(&self) -> bool {
        self.code == MessageCode::SERVICE_UNAVAILABLE.0
    }

    /// Human-readable code string, e.g. `"2.05"`.
    pub fn code_str(&self) -> String {
        format!("{}.{:02}", self.code >> 5, self.code & 0x1f)
    }

    /// Returns retry-after duration for 5.03 responses (spec 07 section 10.2.3).
    ///
    /// Returns `None` for non-5.03 responses. For 5.03 responses, returns
    /// Max-Age value (capped at MAX_BACKOFF_S) or DEFAULT_503_BACKOFF_S.
    pub fn retry_after_s(&self) -> Option<u64> {
        if !self.is_service_unavailable() {
            return None;
        }
        let raw = self
            .max_age
            .map(|v| v as u64)
            .unwrap_or(DEFAULT_503_BACKOFF_S);
        Some(raw.min(MAX_BACKOFF_S))
    }
}

/// Error returned when a peer is backed off or returns 5.03 Service Unavailable.
///
/// Per spec 07 section 10.2.3: "Senders receiving 5.03 MUST back off for the
/// indicated duration."
#[derive(Debug)]
pub struct ServiceUnavailableError {
    /// Peer address that is unavailable.
    pub peer: SocketAddr,
    /// Duration to wait before retrying, in seconds.
    pub retry_after_s: u64,
    /// True if this error is from an active backoff (request blocked before sending).
    pub is_backoff: bool,
}

impl std::fmt::Display for ServiceUnavailableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if self.is_backoff {
            write!(
                f,
                "peer {} is backed off for {}s",
                self.peer, self.retry_after_s
            )
        } else {
            write!(
                f,
                "peer {} returned 5.03, back off for {}s",
                self.peer, self.retry_after_s
            )
        }
    }
}

impl std::error::Error for ServiceUnavailableError {}

/// CoAP client error type.
#[derive(Debug)]
pub enum ClientError {
    /// I/O or transport error.
    Io(std::io::Error),
    /// Peer is unavailable (5.03 received or in backoff).
    ServiceUnavailable(ServiceUnavailableError),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "{}", e),
            Self::ServiceUnavailable(e) => write!(f, "{}", e),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::ServiceUnavailable(e) => Some(e),
        }
    }
}

impl From<std::io::Error> for ClientError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<ServiceUnavailableError> for ClientError {
    fn from(e: ServiceUnavailableError) -> Self {
        Self::ServiceUnavailable(e)
    }
}

/// Stateful CoAP client with 5.03 backoff tracking (spec 07 section 10.2.3).
///
/// Tracks peer backoff state and refuses new requests to peers that are in
/// backoff. Use [`CoapClient::new`] to create a client, then call methods
/// like [`CoapClient::get`], [`CoapClient::post`], etc.
///
/// # Example
///
/// ```ignore
/// let mut client = CoapClient::new();
/// let resp = client.get(addr, "/status").await?;
/// ```
#[derive(Debug, Default)]
pub struct CoapClient {
    /// Peer backoff state: peer -> expiry instant.
    backoffs: HashMap<SocketAddr, Instant>,
}

impl CoapClient {
    /// Create a new CoAP client with no active backoffs.
    pub fn new() -> Self {
        Self::default()
    }

    /// GET coap://[addr][path].
    pub async fn get(&mut self, addr: SocketAddr, path: &str) -> Result<Response, ClientError> {
        self.request(addr, MessageCode::GET, path, None).await
    }

    /// POST coap://[addr][path] with CBOR body.
    pub async fn post(
        &mut self,
        addr: SocketAddr,
        path: &str,
        body: &[u8],
    ) -> Result<Response, ClientError> {
        self.request(addr, MessageCode::POST, path, Some(body))
            .await
    }

    /// PUT coap://[addr][path] with CBOR body.
    pub async fn put(
        &mut self,
        addr: SocketAddr,
        path: &str,
        body: &[u8],
    ) -> Result<Response, ClientError> {
        self.request(addr, MessageCode::PUT, path, Some(body)).await
    }

    /// DELETE coap://[addr][path].
    pub async fn delete(&mut self, addr: SocketAddr, path: &str) -> Result<Response, ClientError> {
        self.request(addr, MessageCode::DELETE, path, None).await
    }

    /// Perform a CoAP request with backoff enforcement (spec 07 section 10.2.3).
    ///
    /// SECURITY: Blocks requests to peers in backoff per spec 07 section 10.2.3.
    /// The spec MUST requirement ("Senders receiving 5.03 MUST back off for the
    /// indicated duration") protects peers from traffic they've explicitly asked
    /// to stop receiving.
    pub async fn request(
        &mut self,
        addr: SocketAddr,
        code: MessageCode,
        path: &str,
        payload: Option<&[u8]>,
    ) -> Result<Response, ClientError> {
        // Check backoff before sending
        if let Some(&expires_at) = self.backoffs.get(&addr) {
            let now = Instant::now();
            if now < expires_at {
                let remaining = expires_at.duration_since(now);
                return Err(ServiceUnavailableError {
                    peer: addr,
                    retry_after_s: remaining.as_secs() + 1,
                    is_backoff: true,
                }
                .into());
            } else {
                // Backoff expired, clear it
                self.backoffs.remove(&addr);
            }
        }

        // Perform the request
        let response = request(addr, code, path, payload).await?;

        // Handle 5.03 response
        if response.is_service_unavailable() {
            let retry_after = response.retry_after_s().unwrap_or(DEFAULT_503_BACKOFF_S);
            let expires_at = Instant::now() + Duration::from_secs(retry_after);
            self.backoffs.insert(addr, expires_at);
            return Err(ServiceUnavailableError {
                peer: addr,
                retry_after_s: retry_after,
                is_backoff: false,
            }
            .into());
        }

        Ok(response)
    }

    /// Clear backoff state for a specific peer (for testing or explicit reset).
    pub fn clear_backoff(&mut self, addr: &SocketAddr) {
        self.backoffs.remove(addr);
    }

    /// Clear all backoff state (for testing or explicit reset).
    pub fn clear_all_backoffs(&mut self) {
        self.backoffs.clear();
    }

    /// Check if a peer is currently backed off.
    pub fn is_backed_off(&self, addr: &SocketAddr) -> bool {
        self.backoffs
            .get(addr)
            .map(|&expires_at| Instant::now() < expires_at)
            .unwrap_or(false)
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

    // Parse Max-Age option (RFC 7252 §5.10.5)
    let mut max_age: Option<u32> = None;
    for opt in packet.options().flatten() {
        if opt.number == OptionNumber::MaxAge as u16 {
            max_age = opt.as_uint().ok();
            break;
        }
    }

    Ok(Response {
        code: packet.code().0,
        payload: packet.payload().to_vec(),
        max_age,
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

    /// Build a minimal CoAP response: Ver=1, Type=ACK, TKL, Code, MID, Token, optional Max-Age, optional payload (RFC 7252).
    fn build_response(
        code: MessageCode,
        mid: u16,
        token: &[u8],
        payload: Option<&[u8]>,
    ) -> Vec<u8> {
        build_response_with_max_age(code, mid, token, None, payload)
    }

    /// Build a CoAP response with optional Max-Age option (RFC 7252 §5.10.5).
    fn build_response_with_max_age(
        code: MessageCode,
        mid: u16,
        token: &[u8],
        max_age: Option<u32>,
        payload: Option<&[u8]>,
    ) -> Vec<u8> {
        let tkl = token.len() as u8;
        assert!(tkl <= 8, "token too long");
        // Ver=1 (bits 7-6), Type=ACK=2 (bits 5-4), TKL (bits 3-0)
        let byte0 = ACK_HEADER | tkl;
        let mid_bytes = mid.to_be_bytes();
        let mut data = vec![byte0, code.0, mid_bytes[0], mid_bytes[1]];
        data.extend_from_slice(token);

        // Add Max-Age option (option number 14) if provided
        if let Some(max_age_val) = max_age {
            // Option delta=14, encode as minimal-length uint
            let value_bytes = encode_uint(max_age_val);
            let len = value_bytes.len();
            assert!(len <= 4);
            // Delta nibble = 14 uses extended format: nibble=13, ext=(14-13)=1
            // For simplicity, encode delta=14 as nibble=14, no extended (delta >= 14 uses 2-byte ext)
            // Actually delta=14 fits in extended 1-byte: nibble=13, ext=1
            data.push(0xD0 | (len as u8)); // delta=13+1=14, len in low nibble
            data.push(0x01); // extended delta = 14 - 13 = 1
            data.extend_from_slice(&value_bytes);
        }

        if let Some(p) = payload {
            if !p.is_empty() {
                data.push(PAYLOAD_MARKER);
                data.extend_from_slice(p);
            }
        }
        data
    }

    /// Encode a u32 as minimal-length CoAP uint option value.
    fn encode_uint(val: u32) -> Vec<u8> {
        if val == 0 {
            vec![]
        } else if val <= 0xFF {
            vec![val as u8]
        } else if val <= 0xFFFF {
            vec![(val >> 8) as u8, val as u8]
        } else if val <= 0xFF_FFFF {
            vec![(val >> 16) as u8, (val >> 8) as u8, val as u8]
        } else {
            vec![
                (val >> 24) as u8,
                (val >> 16) as u8,
                (val >> 8) as u8,
                val as u8,
            ]
        }
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
        let spoofed_resp =
            build_response(MessageCode::CONTENT, attacker_mid, &token, Some(b"fake"));
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
        let spoofed_resp =
            build_response(MessageCode::CONTENT, mid, &attacker_token, Some(b"fake"));
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
        let spoofed_resp = build_response(
            MessageCode::CONTENT,
            attacker_mid,
            &attacker_token,
            Some(b"pwned"),
        );
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

    // ── 5.03 Service Unavailable Tests (spec 07 section 10.2.3) ─────────────

    #[test]
    fn response_is_service_unavailable() {
        let mid = 0x1234;
        let token: [u8; 0] = [];
        let resp_data = build_response(MessageCode::SERVICE_UNAVAILABLE, mid, &token, None);
        let resp = decode(&resp_data, mid, &token).unwrap();
        assert!(resp.is_service_unavailable());
        assert!(!resp.is_success());
        assert_eq!(resp.code_str(), "5.03");
    }

    #[test]
    fn response_with_max_age_parses_correctly() {
        let mid = 0x1234;
        let token: [u8; 0] = [];
        let resp_data = build_response_with_max_age(
            MessageCode::SERVICE_UNAVAILABLE,
            mid,
            &token,
            Some(120),
            None,
        );
        let resp = decode(&resp_data, mid, &token).unwrap();
        assert!(resp.is_service_unavailable());
        assert_eq!(resp.max_age, Some(120));
        assert_eq!(resp.retry_after_s(), Some(120));
    }

    #[test]
    fn response_retry_after_uses_default_when_no_max_age() {
        let mid = 0x1234;
        let token: [u8; 0] = [];
        let resp_data = build_response(MessageCode::SERVICE_UNAVAILABLE, mid, &token, None);
        let resp = decode(&resp_data, mid, &token).unwrap();
        assert!(resp.is_service_unavailable());
        assert_eq!(resp.max_age, None);
        assert_eq!(resp.retry_after_s(), Some(DEFAULT_503_BACKOFF_S));
    }

    #[test]
    fn response_retry_after_caps_at_max() {
        let mid = 0x1234;
        let token: [u8; 0] = [];
        // Max-Age of 10000 seconds should be capped to MAX_BACKOFF_S (3600)
        let resp_data = build_response_with_max_age(
            MessageCode::SERVICE_UNAVAILABLE,
            mid,
            &token,
            Some(10000),
            None,
        );
        let resp = decode(&resp_data, mid, &token).unwrap();
        assert_eq!(resp.max_age, Some(10000));
        assert_eq!(resp.retry_after_s(), Some(MAX_BACKOFF_S));
    }

    #[test]
    fn response_retry_after_none_for_non_503() {
        let mid = 0x1234;
        let token: [u8; 0] = [];
        let resp_data = build_response_with_max_age(
            MessageCode::CONTENT,
            mid,
            &token,
            Some(120),
            Some(b"data"),
        );
        let resp = decode(&resp_data, mid, &token).unwrap();
        assert!(!resp.is_service_unavailable());
        assert_eq!(resp.max_age, Some(120)); // Max-Age is still parsed
        assert_eq!(resp.retry_after_s(), None); // But retry_after is None for non-5.03
    }

    #[test]
    fn client_tracks_backoff_state() {
        let client = CoapClient::new();
        let addr: SocketAddr = "127.0.0.1:5683".parse().unwrap();
        assert!(!client.is_backed_off(&addr));
    }

    #[test]
    fn client_clear_backoff() {
        let mut client = CoapClient::new();
        let addr: SocketAddr = "127.0.0.1:5683".parse().unwrap();
        // Manually insert a backoff
        client
            .backoffs
            .insert(addr, Instant::now() + Duration::from_secs(100));
        assert!(client.is_backed_off(&addr));
        client.clear_backoff(&addr);
        assert!(!client.is_backed_off(&addr));
    }

    #[test]
    fn client_clear_all_backoffs() {
        let mut client = CoapClient::new();
        let addr1: SocketAddr = "127.0.0.1:5683".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.2:5683".parse().unwrap();
        client
            .backoffs
            .insert(addr1, Instant::now() + Duration::from_secs(100));
        client
            .backoffs
            .insert(addr2, Instant::now() + Duration::from_secs(100));
        assert!(client.is_backed_off(&addr1));
        assert!(client.is_backed_off(&addr2));
        client.clear_all_backoffs();
        assert!(!client.is_backed_off(&addr1));
        assert!(!client.is_backed_off(&addr2));
    }

    #[test]
    fn service_unavailable_error_display() {
        let err = ServiceUnavailableError {
            peer: "127.0.0.1:5683".parse().unwrap(),
            retry_after_s: 60,
            is_backoff: false,
        };
        assert!(err.to_string().contains("5.03"));
        assert!(err.to_string().contains("60s"));

        let err_backoff = ServiceUnavailableError {
            peer: "127.0.0.1:5683".parse().unwrap(),
            retry_after_s: 30,
            is_backoff: true,
        };
        assert!(err_backoff.to_string().contains("backed off"));
        assert!(err_backoff.to_string().contains("30s"));
    }

    #[test]
    fn client_error_from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout");
        let client_err: ClientError = io_err.into();
        assert!(matches!(client_err, ClientError::Io(_)));
    }

    #[test]
    fn client_error_from_service_unavailable() {
        let su_err = ServiceUnavailableError {
            peer: "127.0.0.1:5683".parse().unwrap(),
            retry_after_s: 60,
            is_backoff: false,
        };
        let client_err: ClientError = su_err.into();
        assert!(matches!(client_err, ClientError::ServiceUnavailable(_)));
    }
}
